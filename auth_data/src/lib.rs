//! Data layer for authentication feature
//!
//! This module contains the data access layer for the authentication feature,
//! including database entities, repositories, and data-specific error messages.

pub mod entities;
pub mod repositories;
pub mod error;

pub use entities::*;
pub use repositories::*;
pub use error::*; 