# netforge

This is my personal playground for learning low-level network programming in C.

---

## What is this?

I'm building a small collection of C programs to experiment with networking concepts like sockets, protocols, and data packets. This isn't meant to be a polished library or a set of professional tools. It's just a place for me to have fun and figure out how things work from scratch.

The whole idea is to learn by doing.

---

## My Current Experiments

Here's what I've built so far:

* `server`: A simple chat server that can handle just one connection.
* `pollserver`: A simple chat server that can handle multiple clients at once using the `poll()` system call.
* `client`: A basic client to connect to the server and send messages.

I'll be adding more tools as I learn new things.

---

## How to Build and Run

If you want to try them out, here’s how. You'll need `gcc` and `make`.

1.  **Clone the repo:**
    ```sh
    git clone [https://github.com/YOUR_USERNAME/netforge.git](https://github.com/YOUR_USERNAME/netforge.git)
    cd netforge
    ```

2.  **Compile everything:**
    ```sh
    make
    ```
    This puts the programs in the `bin/` folder.

3.  **Run the server and client:**
    Open two separate terminals.

    In the first terminal, start the server:
    ```sh
    ./bin/pollserver
    ```
    In the second terminal, start the client:
    ```sh
    ./bin/client
    ```

---

## A Note on This Project

The code here is for learning purposes. It might be buggy, incomplete, or not follow best practices. That's part of the process! Feel free to look around, but don't use this for anything important.

---

Licensed under the **MIT License**.
