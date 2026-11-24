// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./Errors.sol";


/// @dev Contract implements an upgradeable version of tree which stores
/// elements in order of insertion. When a element is added, it is added
/// to the left most empty leaf in the tree. When an element is deleted,
/// it is replaced with the element in the right most leaf in the tree.
/// Each element in the tree stores the weight of all elements on the left
/// and right side of the node.
contract TreeUpgradeable is Initializable {
    /// @notice Struct that stores the value on the node and the sum of
    /// weights on left and right side of the node.
    /// @param value Value on the node
    /// @param leftSum Sum of nodes on the left side of the current node
    /// @param rightSum Sum of nodes on the right side of the current node
    struct Node {
        uint64 value;
        uint64 leftSum;
        uint64 rightSum;
    }

    /// @notice Mapping of address of a node to it's index in nodes array
    mapping(address => uint256) public addressToIndexMap;

    /// @notice Mapping of index in nodes array to address of the node
    mapping(uint256 => address) public indexToAddressMap;

    /// @notice Array of nodes stored in the tree
    Node[] public nodes;

    uint256[47] __gap;

    function __TreeUpgradeable_init_unchained() internal onlyInitializing {
        _init_tree();
    }

    /// @dev Initializes the tree with 0 element as the first element.
    /// Node indexes start from 1.
    function _init_tree() private {
        require(nodes.length == 0, Errors.INVALID_INIT_STATE);
        // root starts from index 1
        nodes.push(Node(0, 0, 0));
    }

    function nodesInTree() public view returns(uint256) {
        return nodes.length - 1;
    }

    // assumes index is not 0
    function _add_unchecked(uint256 _index, uint64 _value) internal {
        nodes[_index].value += _value;
        while(_index > 1) {
            bool _side = _index % 2 == 0;
            _index = _index >> 1;
            if(_side == true) {
                nodes[_index].leftSum += _value;
            } else {
                nodes[_index].rightSum += _value;
            }
        }
    }

    // assumes index is not 0
    function _sub_unchecked(uint256 _index, uint64 _value) internal {
        nodes[_index].value -= _value;
        while(_index > 1) {
            bool _side = _index % 2 == 0;
            _index = _index >> 1;
            if(_side == true) {
                nodes[_index].leftSum -= _value;
            } else {
                nodes[_index].rightSum -= _value;
            }
        }
    }

    // assumes _addr not already in tree
    function _insert_unchecked(address _addr, uint64 _value) internal {
        uint256 _index = nodes.length;
        nodes.push(Node(0, 0, 0));

        addressToIndexMap[_addr] = _index;
        indexToAddressMap[_index] = _addr;

        _add_unchecked(_index, _value);
    }

    // assumes index is not 0
    function _update_unchecked(uint256 _index, uint64 _value) internal {
        uint64 _currentValue = nodes[_index].value;

        if(_currentValue >= _value) {
            _sub_unchecked(_index, _currentValue - _value);
        } else {
            _add_unchecked(_index, _value - _currentValue);
        }
    }

    // assumes _addr already in tree
    function _update_unchecked(address _addr, uint64 _value) internal {
        _update_unchecked(addressToIndexMap[_addr], _value);
    }

    function _upsert(address _addr, uint64 _value) internal {
        uint256 _index = addressToIndexMap[_addr];
        if(_index == 0) {
            _insert_unchecked(_addr, _value);
        } else {
            _update_unchecked(_index, _value);
        }
    }

    // assumes _addr already in tree at _index
    function _delete_unchecked(address _addr, uint256 _index) internal {
        uint256 _lastNodeIndex = nodes.length - 1;
        address _lastNodeAddress = indexToAddressMap[_lastNodeIndex];
        uint64 _lastNodeValue = nodes[_lastNodeIndex].value;
        // left and right sum will always be 0 for last node

        _sub_unchecked(_lastNodeIndex, _lastNodeValue);

        // only swap if not last node
        if(_index != _lastNodeIndex) {
            _update_unchecked(_index, _lastNodeValue);

            indexToAddressMap[_index] = _lastNodeAddress;
            addressToIndexMap[_lastNodeAddress] = _index;
        }

        delete indexToAddressMap[_lastNodeIndex];
        delete addressToIndexMap[_addr];

        nodes.pop();
    }

    function _deleteIfPresent(address _addr) internal {
        uint256 _index = addressToIndexMap[_addr];
        if(_index == 0) {
            return;
        }

        _delete_unchecked(_addr, _index);
    }

    struct MemoryNode {
        uint256 node; // sorting condition
        uint256 value;
        uint256 left;
        uint256 leftSum;
        uint256 right;
        uint256 rightSum;
    }

    function _selectOne(
        uint256 _rootIndex,
        uint256 _searchNumber,
        MemoryNode[] memory _selectedPathTree,
        uint256 _mRootIndex,
        uint256 _mLastIndex
    )
        internal
        view
        returns (
            uint256, // address of the selected node
            uint256, // balance of the selected node
            uint256 // updated index of the latest element in the memory tree array
        )
    {
        unchecked {
            Node memory _root = nodes[_rootIndex];

            // require(_searchNumber <= _root.leftSum + _root.value + _root.rightSum, "should never happen");

            MemoryNode memory _mRoot;

            // exclusive
            uint256 _leftBound = _root.leftSum;
            // inclusive
            // safemath: can never exceed 2^65
            uint256 _rightBound = _leftBound + _root.value;

            if (_mRootIndex != 0) {
                _mRoot = _selectedPathTree[_mRootIndex];
                // safemath: sums in memory tree can never exceed storage tree
                _leftBound -= _mRoot.leftSum;
                // safemath: sums in memory tree can never exceed storage tree
                _rightBound -= (_mRoot.leftSum + _mRoot.value);
            } else {
                // path always goes through current node, add in memory tree if it does not exist
                // safemath: cannot exceed storage tree size
                ++_mLastIndex;
                _mRootIndex = _mLastIndex;
                _mRoot.node = _rootIndex;
                // do not set properties directly, node does not exist
                _selectedPathTree[_mRootIndex] = _mRoot;
            }

            // check current root
            if (_searchNumber >= _leftBound && _searchNumber < _rightBound) {
                // current root matched, add in memory tree and return
                // safemath: cannot exceed 2^65
                _selectedPathTree[_mRootIndex].value += _root.value;
                return (_rootIndex, _root.value, _mLastIndex);
            } else if (_searchNumber < _leftBound) {  // check left side
                // search on left side
                // separated out due to stack too deep errors
                return _selectLeft(_rootIndex, _searchNumber, _selectedPathTree, _mRoot.left, _mRootIndex, _mLastIndex);
            } else { // has to be on right side
                // search on right side
                // separated out due to stack too deep errors
                return _selectRight(_rootIndex, _searchNumber - _rightBound, _selectedPathTree, _mRoot.right, _mRootIndex, _mLastIndex);
            }
        }
    }

    function _selectLeft(
        uint256 _rootIndex,
        uint256 _searchNumber,
        MemoryNode[] memory _selectedPathTree,
        uint256 _mRootLeft,
        uint256 _mRootIndex,
        uint256 _mLastIndex
    ) internal view returns (uint256, uint256, uint256) {
        unchecked {
            (uint256 _sNode, uint256 _sBalance, uint256 _mTreeSize) = _selectOne(
                // safemath: cannot exceed storage tree size
                _rootIndex * 2, // left node
                _searchNumber,
                _selectedPathTree,
                _mRootLeft,
                _mLastIndex
            );
            // if left is 0, it would have been added in the recursive call
            if (_mRootLeft == 0) {
                // safemath: cannot exceed storage tree size
                _selectedPathTree[_mRootIndex].left = _mLastIndex + 1;
            }
            // safemath: cannot exceed 2^65
            _selectedPathTree[_mRootIndex].leftSum += _sBalance;
            return (_sNode, _sBalance, _mTreeSize);
        }
    }

    function _selectRight(
        uint256 _rootIndex,
        uint256 _searchNumber,
        MemoryNode[] memory _selectedPathTree,
        uint256 _mRootRight,
        uint256 _mRootIndex,
        uint256 _mLastIndex
    ) internal view returns (uint256, uint256, uint256) {
        unchecked {
            (uint256 _sNode, uint256 _sBalance, uint256 _mTreeSize) = _selectOne(
                // safemath: cannot exceed storage tree size
                _rootIndex * 2 + 1, // right node
                _searchNumber,
                _selectedPathTree,
                _mRootRight,
                _mLastIndex
            );
            // if right is 0, it would have been added in the recursive call
            if (_mRootRight == 0) {
                // safemath: cannot exceed storage tree size
                _selectedPathTree[_mRootIndex].right = _mLastIndex + 1;
            }
            // safemath: cannot exceed 2^65
            _selectedPathTree[_mRootIndex].rightSum += _sBalance;
            return (_sNode, _sBalance, _mTreeSize);
        }
    }

    function _selectN(uint256 _randomizer, uint256 _N) internal view returns (address[] memory _selectedNodes) {
        uint256 _nodeCount = nodes.length - 1;
        if(_N > _nodeCount) _N = _nodeCount;
        if(_N == 0) return new address[](0);

        // WARNING - don't declare any memory variables before this point

        MemoryNode[] memory _selectedPathTree;
        // assembly block sets memory for the MemoryNode array but does not zero initialize each value of each struct
        // To ensure random values are never accessed for the MemoryNodes, we always initialize before using an array node
        assembly {
            let _pos := mload(0x40)
            mstore(0x40, add(_pos, 2688))
            mstore(_selectedPathTree, 83)
        }

        Node memory _root = nodes[1];
        _selectedPathTree[1] = MemoryNode(1, 0, 0, 0, 0, 0);

        uint256 _mLastIndex = 1;
        // added in next line to save gas and avoid overflow checks
        uint256 _totalWeightInTree = _root.value;
        unchecked {
            _totalWeightInTree += _root.leftSum + _root.rightSum;
        }
        uint256 _sumOfBalancesOfSelectedNodes = 0;
        _selectedNodes = new address[](_N);

        for (uint256 _index = 0; _index < _N; ) {
            _randomizer = uint256(keccak256(abi.encode(_randomizer, _index)));
            // yes, not the right way to get exact uniform distribution
            // should be really close given the ranges
            uint256 _searchNumber = _randomizer % (_totalWeightInTree - _sumOfBalancesOfSelectedNodes);
            uint256 _node;
            uint256 _selectedNodeBalance;

            (_node, _selectedNodeBalance, _mLastIndex) = _selectOne(
                1, // index of root
                _searchNumber,
                _selectedPathTree,
                1,
                _mLastIndex
            );

            _selectedNodes[_index] = indexToAddressMap[uint32(_node)];
            unchecked {
                _sumOfBalancesOfSelectedNodes += _selectedNodeBalance;
                ++_index;
            }
        }
        return _selectedNodes;
    }
}
