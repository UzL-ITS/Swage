# Hammerers

This directory contains hammering strategy modules for the Swage framework. Each subdirectory is a separate crate that implements the `swage_core::hammerer::Hammering` trait.

## Modular Structure

The Swage framework is designed to be highly modular. Hammerers are discovered and registered at compile time. The main executable, `hammer`, can then use any of the available hammerers by specifying the `--hammerer` command-line argument.

## Adding a New Hammerer

To add a new hammerer (e.g., `my-hammerer`):

1.  **Create a new crate**:
    Create a new directory `swage-my-hammerer` inside the `hammerers/` directory. The crate name must start with `swage-` for it to be automatically discovered.

2.  **Implement the `Hammering` trait**:
    In your new crate, define a struct and implement the `swage_core::hammerer::Hammering` trait for it.

    ```rust
    // in hammerers/swage-my-hammerer/src/lib.rs
    use swage_core::hammerer::Hammering;

    pub struct MyHammerer { /* ... */ }

    impl Hammering for MyHammerer {
        // ... implement the trait methods ...
    }
    ```

3.  **Update the workspace**:
    Run the `update_modules.sh` script from the root of the repository. This script will automatically find your new crate and add it to the workspace's `Cargo.toml`.

    ```sh
    ./update_modules.sh
    ```

    **Do not manually edit the module dependencies in the root `Cargo.toml`**. The `discover_modules!` macro and this script handle module registration.

4.  **Use the new hammerer**:
    You can now use your new hammerer with the `hammer` binary:

    ```sh
    cargo run --release --bin=hammer -- --hammerer my-hammerer ...
    ```
