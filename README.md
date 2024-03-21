# Patch Tuesday Report

This repository contains a script to fetch and analyze Microsoft Patch Tuesday security updates.

## Overview

The script retrieves information about Microsoft security updates for a specified month and year, analyzes the vulnerabilities, and provides statistics such as the total number of vulnerabilities, types of vulnerabilities, and highest-rated vulnerabilities.

## Usage

To use the script, follow these steps:

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/Robinzor/patch-tuesday.git
    ```

2. Navigate to the cloned repository directory:

    ```bash
    cd patch-tuesday
    ```

3. Run the script with the desired month and year in the format YYYY-MMM:

    ```bash
    python patchtuesday.py YYYY-MMM
    ```

    Replace `YYYY-MMM` with the desired month and year (e.g., `2024-Mar`).

4. Optionally, if you want to bypass the day check and force the update, you can use the `--force` option:

    ```bash
    python patchtuesday.py YYYY-MMM --force
    ```

    The `--force` option allows you to bypass the day check and update the report even if it's not the second Tuesday of the month.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
