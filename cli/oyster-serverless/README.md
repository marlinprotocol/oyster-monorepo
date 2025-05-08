# Oyster Serverless CLI

The Oyster Serverless CLI is a command-line tool that simplifies the development and deployment of serverless functions on the Oyster Severless platform. It supports local testing, Job deployment, and recurring job scheduling, enabling developers to efficiently build and manage secure, scalable serverless applications.


## 🛠️ Installation

### From source


To build from source, ensure you have the following installed:
- **Rust**: The programming language required for building the project.
- **Cargo**: The Rust package manager and build system.

```bash
git clone https://github.com/marlinprotocol/oyster-monorepo.git
cd cli/oyster-serverless
cargo build --release
```

### Using nix

Supports both Linux and MacOS builds.

```
# linux amd64
nix build .#packages.x86_64-linux.default.cli.oyster-serverless.default

# linux arm64
nix build .#packages.aarch64-linux.default.cli.oyster-serverless.default

# macOS arm64 (Apple Silicon)
nix build .#packages.aarch64-darwin.default.cli.oyster-serverless.default
```

## 👨‍⚕️ Doctor

```
oyster-serverless doctor
```
Checks if docker is installed

## 👷‍♀️ Local development
Below are the steps for developing and testing your oyster-serverless functions.

1. **Create the project**
    ```bash
    oyster-serverless new
    ```
    **Arguments:**
    - `name`: Name of the project

    > **Note:** This command creates a new project with the provided name and gives users the option to select a template or provide a raw GitHub code link for their Workerd JavaScript code.



2. **Navigate into the project directory**
    ```bash
    cd first-example-project
    ```

3. **Modify the JS file** as needed by following the workerd guideline.


4. **Test the setup locally** by running the following command:

    > ⚠️ **Note:** Depending on your Docker setup, you might need to run this command with root privileges.

    ```bash
    oyster-serverless dev
    ```

    If you encounter issues, try running it with `sudo`:

    ```bash
    sudo oyster-serverless dev
    ```


    **Arguments:**
    - `input-file` (Optional) : Input file path for the workerd program.



## 🚀 Deploy Function

Deploy JavaScript code to the Oyster Serverless platform.

```bash
oyster-serverless deploy
```

**Arguments:**

- `wallet-private-key`: Private key for transactions.
- `contract-address` *(optional)*: Overrides the default serverless contract address.
- `minified` *(optional)*: Minify the JS file.

> Note : Defaults to worker.js created by the new project command

**Output:**

- Transaction hash of the saved code.

## ⚙️ Create Job

Create a serverless job on the platform.

```bash
oyster-serverless job create
```

**Arguments:**

- `wallet-private-key`: Private key for transactions.
- `callback-contract-address`: Any address.
- `env` *(optional)*: Execution environment (defaults to 1).
- `refund-account` *(optional)*: Address to receive compensation if the job fails (defaults to sender's address).
- `code-hash`: Transaction hash of the deployed JS code.
- `input-file` *(optional)*: Path for worker input file
- `user-timeout`: Maximum time allowed for executors to complete the computation.
- `max-gas-price` *(optional)*: Multiplier (e.g: 1.5,2,2.5).
- `callback-gas-limit`: Gas limit for the callback function.

**Sample command:**
```
oyster-serverless job create --wallet-private-key *** --code-hash 0x6a7478d2ad9c041bef6f0d975ad6d787c42609ec4f700afcba1679eb18ac08d1 --input-file input.json --user-timeout 5000 --callback-contract-address 0x67a0cc925b787eCdb470315E4e7DBc107370A8f4 --callback-gas-limit 1000
```

## 📬 Fetch Job Response

Fetch the response of a serverless job.


```bash
oyster-serverless job fetch-response
```

**Arguments:**

- `job-transaction-hash`: Transaction hash returned by the create job command.

## 🚫 Cancel Job

Cancel a serverless job.

> ⚠️ **Note:** Need to wait for relay overall timeout after the job is created.
```bash
oyster-serverless job cancel
```

**Arguments:**
- `wallet-private-key`: Private key for transactions.
- `job-transaction-hash`: Transaction hash returned by the create job command.


## 🔁 Create Subscription

Create a recurring serverless job (subscription).

```bash
oyster-serverless subscription create
```

**Arguments:**
- `wallet-private-key`: Private key for transactions.
- `env` *(optional)*: Execution environment (defaults to 1).
- `callback-contract-address`: Any address.
- `start-timestamp` *(optional)*: Timestamp for starting the sub.
- `code-hash`: Transaction hash of the deployed JS code.
- `input-file` *(optional)*: Path for worker input file
- `periodic-gap` *(optional)*: Interval at which the function will be executed (e.g., every 30 seconds).
- `termination-timestamp`*(optional)*: Timestamp to terminate the subscription.
- `user-timeout`: Time limit for executors.
- `max-gas-price` *(optional)*: Multiplier (e.g: 1.5,2,2.5).
- `callback-gas-limit`: Gas limit for the callback function.
- `refund-account` *(optional)*: Address to receive compensation if the job fails (defaults to sender's address).

**Sample command:**
```
oyster-serverless subscription create --wallet-private-key **** --code-hash 0x6a7478d2ad9c041bef6f0d975ad6d787c42609ec4f700afcba1679eb18ac08d1 --input-file input.json --user-timeout 5000 --callback-contract-address 0x67a0cc925b787eCdb470315E4e7DBc107370A8f4 --callback-gas-limit 1000
```

> **Note:** If not provided as arguments, the `start-timestamp`, `termination-timestamp`, and `periodic-gap` values can be entered through interactive prompts.

## 📬 Fetch Subscription Response

Fetch the response of a serverless subscription.


```bash
oyster-serverless subscription fetch-response
```

**Arguments:**

- `subscription-transaction-hash`: Transaction hash returned by the create subscription command.
- `stream` : If set, listen for job responses until subscription is terminated. Else, get the responses received till the current time. 


## ⬆️ Update Subscription

Update the termination timestamp for the serverless subscription.

```bash
oyster-serverless update
```

**Arguments:**
- `wallet-private-key`: Private key for transactions.
- `subscription-transaction-hash`: Transaction hash returned by the create subscription command.
- `termination-timestamp` - Timestamp for terminating the job.


## 🛑 Terminate subscription

Terminate a subscription

```bash
oyster-serverless terminate
```

**Arguments:**
- `wallet-private-key`: Private key for transactions.
- `subscription-transaction-hash`: Transaction hash returned by the create subscription command.

## 💸 Refund subscription deposits

Refund deposits for a terminated subscription

```bash
oyster-serverless refund-deposits
```

**Arguments:**
- `wallet-private-key`: Private key for transactions.
- `subscription-transaction-hash`: Transaction hash returned by the create subscription command.