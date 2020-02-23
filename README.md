# DNS
A DNS client, server, and packet parser.

# Motivation

This is purely a learning project.  I've been wanting to play around with Rust for awhile, as the borrow checker, zero-cost abstractions, and lack of objects has piqued my interest for some time.  Having finished [the Rust book](https://doc.rust-lang.org/book/title-page.html) and written a few small data structures in Rust, I wanted to try to implement something that would expose me to some of the nuances of the language, things like lifetimes, traits, bit twiddling, network programming, and concurrency.

On the whole, I've been very impressed with the expressiveness and simplicity of the language.  Coming from largely a Python + Java + JS background, I had a base assumption that moving from dynamic types and garbage collection to static types and loads of compilation errors would slow me down significantly.  I was surprised to find how helpful compiler-driven development can be, with many of the error messages exactly describing the problem I had, plus a suggested fix.

# Run

To run the packet parser, save a DNS packet to a test file at the root of the source tree, then run:

`cargo run --bin dnsparser <my_file>`

You'll need to generate a DNS packet to use above.  That can be done with the following:

```bash
# listen for packets locally on a port, saving to a file
nc -c -l 1234 > query.txt
# Send a DNS question to nc, which will then be saved to a file.
dig @127.0.0.1 -p 1234 google.com

# To generate a packet response to be parsed, send off the request and save to a file
nc -u 8.8.8.8 53 < query.txt > response.txt
```

To run the DNS client, run:

`cargo run --bin dnsclient google.com`

Finally, to run the DNS server, run:

`cargo run --bin dnsserver`

# Future Work

I'm hoping to find time to improve the performance of the server by implementing with threads or even the newly-released async/await API.

# Credits

Special thanks to [Emil Hernvall's](https://github.com/EmilHernvall/dnsguide) DNS primer, which provided a quick refresher of the DNS protocol and the Rust code which inspired much of this implementation.
