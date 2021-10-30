# memory-rs
Rust library to interract with memory written in rust

It comes with:
* Pattern scanner (Return address for a pattern given).

A pattern example:
```
04 ?? 34 A4 ?? ?? ?? 90
```

* Memory reader (read an address given and cast it to type given)
An example:
```rust
let address: usize = 0x000000
let byte = read_ptr::<u8>(address).unwrap()
println!("{}", byte);
```
* Memory writter (write data to a given address)
An example:
```
let address: usize = 0x000000
write_ptr::<u8>(address, 0).unwrap();
```
