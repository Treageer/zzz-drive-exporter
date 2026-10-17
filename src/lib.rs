#![allow(dead_code)]

// The standalone package carries its verified protocol implementation directly;
// it must not depend on the sibling research repository at build time.
include!("core.rs");
include!("single_pad.rs");
include!("export_api.rs");
