//! Versioned bootstrap control-plane messages. Media and management RPCs are not implemented yet.
#![forbid(unsafe_code)]
pub mod bootstrap {
    tonic::include_proto!("rustctrl.bootstrap.v1");
}
pub mod auth {
    tonic::include_proto!("rustctrl.auth.v1");
}
