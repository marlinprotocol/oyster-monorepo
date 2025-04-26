# Oyster Serverless CLI

The Oyster Serverless CLI is a command-line tool that simplifies the development and deployment of serverless functions on the Oyster Severless platform. It supports local testing, Job deployment, and recurring job scheduling, enabling developers to efficiently build and manage secure, scalable serverless applications.

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

3. **Modify the JS file** as needed by following the worked guideline.


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



