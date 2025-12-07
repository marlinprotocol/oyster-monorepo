# Nitro Enclave Logger

A simple and efficient logging server designed to run inside the host machine to stream logs from the AWS Nitro Enclave.

1. GET `logs/stream?start_from=100` -- Creates an SSE connection which can be listened to by the client to access realtime logs. `start_from` defaults to `tail-log-id`.    
2. GET `/logs/history?log_id=50&offset=10` -- Responds with the logs starting with `offset` number of logs starting from log id = `log_id`. Omitting log_id param will provide latest produced offset number of logs.
3. GET `logs/tail-log-id` -- Responds with the id of the last received log
4. GET `/logs` -- Renders html page to both stream logs realtime and retrieve existing logs. 

### Building the Server

1. Clone the repository:

    ```bash
    git clone https://github.com/marlinprotocol/oyster-monorepo.git
    ```

2. Navigate to the project directory:

    ```bash
    cd initialization/logger
    ```

3. Build the project in release mode:

    ```bash
    cargo build --release
    ```

### Running the Server

Before running the server, you need to grant it permission to bind to server port (default = 516). This is required because ports below 1024 are privileged, and binding to them normally requires root access.

1. Since the program by default uses port 516, run the command below to allow the program to bind to this privileged port:

    ```bash
    sudo setcap 'cap_net_bind_service=+ep' ./target/release/logger
    ```

2. After setting the capabilities, you can run the server:

    ```bash
    ./target/release/logger
    ```

3. The server will start and listen for http requests on port 516.

## Additional Information

- Ensure your firewall and security groups allow traffic on port 516 if you intend to access the server from outside the host machine.
- To reapply the capability (`setcap`) on the binary, run the command again after each rebuild.
