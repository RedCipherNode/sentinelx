//! Assessment.
//!
//! This module summarizes analysis results into human-readable
//! security assessments.
//!
//! Every assessment must be supported by observations.

use crate::{Finding, Observation};

#[derive(Debug)]
pub struct Assessment {
    pub summary: String,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
}
