//! Reporting Module
//!
//! Generates comprehensive reports on governance activities, treasury status, and participation metrics

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{Utc, DateTime};
use crate::{
    proposal::{Proposal, ProposalState},
    vote::Vote,
    did::DidRegistry, 
    treasury::TreasuryManager,
};

// Report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    GovernanceActivity,     // Overall governance activity summary
    TreasuryStatus,        // Treasury financial status
    ProposalAnalysis,      // Detailed proposal analysis
    ParticipationMetrics,  // Voter participation metrics
    DIDMetrics,           // DID registration and activity metrics
    FinancialSummary,     // Financial flows and disbursements
}

// Time period for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportPeriod {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly,
    Custom { start: u64, end: u64 },
}

// Governance activity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceActivityReport {
    pub period: ReportPeriod,
    pub total_proposals: usize,
    pub proposals_by_status: HashMap<String, usize>,
    pub proposals_by_category: HashMap<String, usize>,
    pub total_votes_cast: usize,
    pub unique_voters: usize,
    pub average_participation_rate: f64,
    pub consensus_outcomes: HashMap<String, usize>,
    pub generated_at: u64,
}

// Treasury status report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStatusReport {
    pub total_balance: f64,
    pub total_reserved: f64,
    pub total_available: f64,
    pub account_balances: HashMap<String, f64>,
    pub pending_disbursements: usize,
    pub pending_disbursement_amount: f64,
    pub total_disbursed_period: f64,
    pub disbursements_by_category: HashMap<String, f64>,
    pub period: ReportPeriod,
    pub generated_at: u64,
}

// Participation metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationMetricsReport {
    pub period: ReportPeriod,
    pub total_eligible_voters: usize,
    pub active_voters: usize,
    pub voter_participation_rate: f64,
    pub votes_per_proposal: HashMap<String, usize>,
    pub top_voters: Vec<VoterActivity>,
    pub participation_trend: Vec<PeriodActivity>,
    pub generated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterActivity {
    pub did_id: String,
    pub votes_cast: usize,
    pub participation_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodActivity {
    pub period_start: u64,
    pub period_end: u64,
    pub unique_voters: usize,
    pub total_votes: usize,
    pub participation_rate: f64,
}

// DID metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDMetricsReport {
    pub period: ReportPeriod,
    pub total_dids: usize,
    pub active_dids: usize,
    pub new_dids_period: usize,
    pub deactivated_dids_period: usize,
    pub dids_by_network: HashMap<String, usize>,
    pub eligible_voters: usize,
    pub ineligible_voters: usize,
    pub average_wallets_per_did: f64,
    pub generated_at: u64,
}

// Financial summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialSummaryReport {
    pub period: ReportPeriod,
    pub opening_balance: f64,
    pub closing_balance: f64,
    pub total_inflows: f64,
    pub total_outflows: f64,
    pub net_change: f64,
    pub disbursements_by_category: HashMap<String, f64>,
    pub largest_disbursements: Vec<DisbursementSummary>,
    pub generated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementSummary {
    pub request_id: String,
    pub amount: f64,
    pub category: String,
    pub recipient: String,
    pub description: String,
    pub executed_at: u64,
}

// Main reporting engine
pub struct ReportingEngine {
    report_cache: HashMap<String, serde_json::Value>,
    last_generated: HashMap<String, u64>,
}

impl ReportingEngine {
    pub fn new() -> Self {
        ReportingEngine {
            report_cache: HashMap::new(),
            last_generated: HashMap::new(),
        }
    }
    
    pub fn generate_governance_activity_report(
        &mut self,
        proposals: &HashMap<String, Proposal>,
        votes: &HashMap<String, Vec<Vote>>,
        period: ReportPeriod,
    ) -> GovernanceActivityReport {
        let (start_time, end_time) = self.get_period_bounds(&period);
        
        // Filter proposals by period
        let period_proposals: Vec<&Proposal> = proposals.values()
            .filter(|p| p.created_at >= start_time && p.created_at <= end_time)
            .collect();
        
        // Count proposals by status
        let mut proposals_by_status = HashMap::new();
        let mut proposals_by_category = HashMap::new();
        
        for proposal in &period_proposals {
            let status = format!("{:?}", proposal.state);
            *proposals_by_status.entry(status).or_insert(0) += 1;
            
            let category = format!("{:?}", proposal.category);
            *proposals_by_category.entry(category).or_insert(0) += 1;
        }
        
        // Count votes and voters
        let mut total_votes = 0;
        let mut unique_voters = std::collections::HashSet::new();
        let mut participation_rates = Vec::new();
        let mut consensus_outcomes = HashMap::new();
        
        for proposal in &period_proposals {
            if let Some(proposal_votes) = votes.get(&proposal.id) {
                let period_votes: Vec<&Vote> = proposal_votes.iter()
                    .filter(|v| v.timestamp >= start_time && v.timestamp <= end_time)
                    .collect();
                
                total_votes += period_votes.len();
                
                for vote in period_votes {
                    unique_voters.insert(vote.did_id.clone());
                }
                
                // Calculate participation rate for this proposal
                // Participation calculation placeholder: total_eligible_voters field does not exist
                // let participation = ...; // Implement with available fields if needed
                participation_rates.push(0.0); // Placeholder for participation rate
                
                // Record consensus outcome
                if proposal.state != ProposalState::Draft && proposal.state != ProposalState::Voting {
                    let outcome = format!("{:?}", proposal.state);
                    *consensus_outcomes.entry(outcome).or_insert(0) += 1;
                }
            }
        }
        
        let average_participation_rate = if participation_rates.is_empty() {
            0.0
        } else {
            participation_rates.iter().sum::<f64>() / participation_rates.len() as f64
        };
        
        GovernanceActivityReport {
            period,
            total_proposals: period_proposals.len(),
            proposals_by_status,
            proposals_by_category,
            total_votes_cast: total_votes,
            unique_voters: unique_voters.len(),
            average_participation_rate,
            consensus_outcomes,
            generated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn generate_treasury_status_report(
        &mut self,
        treasury_manager: &TreasuryManager,
        period: ReportPeriod,
    ) -> TreasuryStatusReport {
        let stats = treasury_manager.get_treasury_stats();
        
        // Get account balances
        let mut account_balances = HashMap::new();
        for account_type in &["treasury_main", "treasury_reserve", "treasury_operations", "treasury_development", "treasury_community"] {
            if let Some(account) = treasury_manager.get_account(account_type) {
                account_balances.insert(account_type.to_string(), account.balance);
            }
        }
        
        // Get pending disbursements
        let pending_disbursements = treasury_manager.list_pending_disbursements();
        let pending_amount: f64 = pending_disbursements.iter().map(|d| d.amount).sum();
        
        // Calculate disbursements by category for the period
        let (start_time, end_time) = self.get_period_bounds(&period);
        let mut disbursements_by_category = HashMap::new();
        let mut total_disbursed_period = 0.0;
        
        // Note: In a real implementation, we'd need access to historical disbursement data
        // For now, we'll use placeholder logic
        
        TreasuryStatusReport {
            total_balance: stats.total_balance,
            total_reserved: stats.total_reserved,
            total_available: stats.total_available,
            account_balances,
            pending_disbursements: pending_disbursements.len(),
            pending_disbursement_amount: pending_amount,
            total_disbursed_period,
            disbursements_by_category,
            period,
            generated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn generate_participation_metrics_report(
        &mut self,
        did_registry: &DidRegistry,
        votes: &HashMap<String, Vec<Vote>>,
        proposals: &HashMap<String, Proposal>,
        period: ReportPeriod,
    ) -> ParticipationMetricsReport {
        let (start_time, end_time) = self.get_period_bounds(&period);
        
        // Count total eligible voters
        let total_eligible_voters = did_registry.get_total_eligible_voters();
        
        // Count active voters in period
        let mut active_voter_dids = std::collections::HashSet::new();
        let mut votes_per_proposal = HashMap::new();
        let mut voter_activity_map: HashMap<String, usize> = HashMap::new();
        
        for (proposal_id, proposal_votes) in votes {
            let period_votes: Vec<&Vote> = proposal_votes.iter()
                .filter(|v| v.timestamp >= start_time && v.timestamp <= end_time)
                .collect();
            
            votes_per_proposal.insert(proposal_id.clone(), period_votes.len());
            
            for vote in period_votes {
                active_voter_dids.insert(vote.did_id.clone());
                *voter_activity_map.entry(vote.did_id.clone()).or_insert(0) += 1;
            }
        }
        
        // Calculate participation rate
        let voter_participation_rate = if total_eligible_voters > 0 {
            (active_voter_dids.len() as f64 / total_eligible_voters as f64) * 100.0
        } else {
            0.0
        };
        
        // Get top voters
        let mut top_voters: Vec<VoterActivity> = voter_activity_map.iter()
            .map(|(did_id, vote_count)| {
                let participation_rate = if votes_per_proposal.len() > 0 {
                    (*vote_count as f64 / votes_per_proposal.len() as f64) * 100.0
                } else {
                    0.0
                };
                
                VoterActivity {
                    did_id: did_id.clone(),
                    votes_cast: *vote_count,
                    participation_rate,
                }
            })
            .collect();
        
        top_voters.sort_by(|a, b| b.votes_cast.cmp(&a.votes_cast));
        top_voters.truncate(10); // Top 10 voters
        
        // Generate participation trend (simplified)
        let participation_trend = vec![PeriodActivity {
            period_start: start_time,
            period_end: end_time,
            unique_voters: active_voter_dids.len(),
            total_votes: voter_activity_map.values().sum(),
            participation_rate: voter_participation_rate,
        }];
        
        ParticipationMetricsReport {
            period,
            total_eligible_voters,
            active_voters: active_voter_dids.len(),
            voter_participation_rate,
            votes_per_proposal,
            top_voters,
            participation_trend,
            generated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn generate_did_metrics_report(
        &mut self,
        did_registry: &DidRegistry,
        period: ReportPeriod,
    ) -> DIDMetricsReport {
        let (start_time, end_time) = self.get_period_bounds(&period);
        
        let active_dids = did_registry.list_active_dids();
        let total_dids = active_dids.len();
        
        // Count DIDs by network
        let mut dids_by_network = HashMap::new();
        let mut total_wallets = 0;
        
        for did in &active_dids {
            *dids_by_network.entry(did.network.clone()).or_insert(0) += 1;
            total_wallets += did.wallet_addresses.len();
        }
        
        let average_wallets_per_did = if total_dids > 0 {
            total_wallets as f64 / total_dids as f64
        } else {
            0.0
        };
        
        // Note: In a real implementation, we'd track historical DID creation/deactivation
        let new_dids_period = 0; // Placeholder
        let deactivated_dids_period = 0; // Placeholder
        
        let eligible_voters = did_registry.get_total_eligible_voters();
        let ineligible_voters = total_dids - eligible_voters;
        
        DIDMetricsReport {
            period,
            total_dids,
            active_dids: total_dids,
            new_dids_period,
            deactivated_dids_period,
            dids_by_network,
            eligible_voters,
            ineligible_voters,
            average_wallets_per_did,
            generated_at: Utc::now().timestamp() as u64,
        }
    }
    
    pub fn export_report_to_json(&self, report: &impl Serialize) -> Result<String, String> {
        serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report: {}", e))
    }
    
    pub fn cache_report(&mut self, report_key: String, report: serde_json::Value) {
        let now = Utc::now().timestamp() as u64;
        self.report_cache.insert(report_key.clone(), report);
        self.last_generated.insert(report_key, now);
    }
    
    pub fn get_cached_report(&self, report_key: &str, max_age_seconds: u64) -> Option<&serde_json::Value> {
        if let Some(last_gen) = self.last_generated.get(report_key) {
            let now = Utc::now().timestamp() as u64;
            if now - last_gen < max_age_seconds {
                return self.report_cache.get(report_key);
            }
        }
        None
    }
    
    fn get_period_bounds(&self, period: &ReportPeriod) -> (u64, u64) {
        let now = Utc::now().timestamp() as u64;
        
        match period {
            ReportPeriod::Daily => (now - 86400, now),
            ReportPeriod::Weekly => (now - 604800, now),
            ReportPeriod::Monthly => (now - 2592000, now),
            ReportPeriod::Quarterly => (now - 7776000, now),
            ReportPeriod::Yearly => (now - 31536000, now),
            ReportPeriod::Custom { start, end } => (*start, *end),
        }
    }
}

// Utility functions for report generation
impl ReportingEngine {
    pub fn generate_comprehensive_report(
        &mut self,
        proposals: &HashMap<String, Proposal>,
        votes: &HashMap<String, Vec<Vote>>,
        did_registry: &DidRegistry,
        treasury_manager: &TreasuryManager,
        period: ReportPeriod,
    ) -> serde_json::Value {
        let governance_report = self.generate_governance_activity_report(proposals, votes, period.clone());
        let treasury_report = self.generate_treasury_status_report(treasury_manager, period.clone());
        let participation_report = self.generate_participation_metrics_report(did_registry, votes, proposals, period.clone());
        let did_report = self.generate_did_metrics_report(did_registry, period.clone());
        
        serde_json::json!({
            "report_type": "comprehensive",
            "period": period,
            "generated_at": Utc::now().timestamp(),
            "governance_activity": governance_report,
            "treasury_status": treasury_report,
            "participation_metrics": participation_report,
            "did_metrics": did_report
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_report_period_bounds() {
        let engine = ReportingEngine::new();
        let now = Utc::now().timestamp() as u64;
        
        let (start, end) = engine.get_period_bounds(&ReportPeriod::Daily);
        assert!(end - start == 86400);
        assert!(end <= now + 1); // Allow 1 second tolerance
        
        let (start, end) = engine.get_period_bounds(&ReportPeriod::Custom { start: 1000, end: 2000 });
        assert_eq!(start, 1000);
        assert_eq!(end, 2000);
    }
    
    #[test]
    fn test_report_caching() {
        let mut engine = ReportingEngine::new();
        let test_report = serde_json::json!({"test": "data"});
        
        engine.cache_report("test_report".to_string(), test_report.clone());
        
        // Should be cached and retrievable
        let cached = engine.get_cached_report("test_report", 3600);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), &test_report);
        
        // Should not be retrievable if max age is 0
        let expired = engine.get_cached_report("test_report", 0);
        assert!(expired.is_none());
    }
}
