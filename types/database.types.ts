import type {
  AttackSimulationResult,
  RemediationSuggestion,
  ScanStatus,
  Severity,
  SeverityBreakdown,
  SupportedLanguage,
  VulnerabilityCategory,
  VulnerabilityStatus,
} from "./security.types";
import type { ReportFormat, SecurityReportPayload } from "./report.types";

/**
 * Strongly-typed Supabase PostgreSQL schema definition.
 * Kept in sync with `/database/schema.sql`.
 */
export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          email: string;
          full_name: string | null;
          avatar_url: string | null;
          role: "user" | "admin";
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id: string;
          email: string;
          full_name?: string | null;
          avatar_url?: string | null;
          role?: "user" | "admin";
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          email?: string;
          full_name?: string | null;
          avatar_url?: string | null;
          role?: "user" | "admin";
          updated_at?: string;
        };
        Relationships: [];
      };
      scans: {
        Row: {
          id: string;
          user_id: string;
          project_name: string;
          file_name: string;
          language: SupportedLanguage;
          source_code: string;
          code_hash: string;
          ai_model_source: string | null;
          status: ScanStatus;
          risk_score: number;
          risk_grade: "A" | "B" | "C" | "D" | "F";
          summary: string;
          severity_breakdown: SeverityBreakdown;
          executed_rules_count: number;
          duration_ms: number;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          project_name: string;
          file_name: string;
          language: SupportedLanguage;
          source_code: string;
          code_hash: string;
          ai_model_source?: string | null;
          status?: ScanStatus;
          risk_score?: number;
          risk_grade?: "A" | "B" | "C" | "D" | "F";
          summary?: string;
          severity_breakdown?: SeverityBreakdown;
          executed_rules_count?: number;
          duration_ms?: number;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          project_name?: string;
          file_name?: string;
          language?: SupportedLanguage;
          status?: ScanStatus;
          risk_score?: number;
          risk_grade?: "A" | "B" | "C" | "D" | "F";
          summary?: string;
          severity_breakdown?: SeverityBreakdown;
          executed_rules_count?: number;
          duration_ms?: number;
          updated_at?: string;
        };
        Relationships: [];
      };
      vulnerabilities: {
        Row: {
          id: string;
          scan_id: string;
          user_id: string;
          rule_id: string;
          title: string;
          description: string;
          explanation: string;
          severity: Severity;
          category: VulnerabilityCategory;
          cwe_id: string;
          owasp_category: string;
          confidence: number;
          line_start: number;
          column_start: number;
          line_end: number;
          column_end: number;
          code_snippet: string;
          matched_text: string;
          remediation: RemediationSuggestion;
          status: VulnerabilityStatus;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          user_id: string;
          rule_id: string;
          title: string;
          description: string;
          explanation: string;
          severity: Severity;
          category: VulnerabilityCategory;
          cwe_id: string;
          owasp_category: string;
          confidence: number;
          line_start: number;
          column_start: number;
          line_end: number;
          column_end: number;
          code_snippet: string;
          matched_text: string;
          remediation: RemediationSuggestion;
          status?: VulnerabilityStatus;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          status?: VulnerabilityStatus;
          remediation?: RemediationSuggestion;
          updated_at?: string;
        };
        Relationships: [];
      };
      attack_simulations: {
        Row: {
          id: string;
          scan_id: string;
          vulnerability_id: string;
          user_id: string;
          rule_id: string;
          attack_name: string;
          mitre_attack_technique: string;
          severity: Severity;
          likelihood: "low" | "medium" | "high";
          simulation_payload: AttackSimulationResult;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          vulnerability_id: string;
          user_id: string;
          rule_id: string;
          attack_name: string;
          mitre_attack_technique: string;
          severity: Severity;
          likelihood: "low" | "medium" | "high";
          simulation_payload: AttackSimulationResult;
          created_at?: string;
        };
        Update: {
          simulation_payload?: AttackSimulationResult;
        };
        Relationships: [];
      };
      security_reports: {
        Row: {
          id: string;
          scan_id: string;
          user_id: string;
          title: string;
          format: ReportFormat;
          report_payload: SecurityReportPayload;
          markdown_content: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          user_id: string;
          title: string;
          format: ReportFormat;
          report_payload: SecurityReportPayload;
          markdown_content?: string | null;
          created_at?: string;
        };
        Update: {
          title?: string;
          format?: ReportFormat;
          report_payload?: SecurityReportPayload;
          markdown_content?: string | null;
        };
        Relationships: [];
      };
      custom_rules: {
        Row: {
          id: string;
          user_id: string;
          rule_key: string;
          name: string;
          description: string;
          explanation: string;
          severity: Severity;
          category: VulnerabilityCategory;
          cwe_id: string;
          owasp_category: string;
          languages: SupportedLanguage[];
          pattern: string;
          pattern_flags: string;
          remediation: RemediationSuggestion;
          enabled: boolean;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          rule_key: string;
          name: string;
          description: string;
          explanation: string;
          severity: Severity;
          category: VulnerabilityCategory;
          cwe_id: string;
          owasp_category: string;
          languages: SupportedLanguage[];
          pattern: string;
          pattern_flags?: string;
          remediation: RemediationSuggestion;
          enabled?: boolean;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          name?: string;
          description?: string;
          explanation?: string;
          severity?: Severity;
          category?: VulnerabilityCategory;
          cwe_id?: string;
          owasp_category?: string;
          languages?: SupportedLanguage[];
          pattern?: string;
          pattern_flags?: string;
          remediation?: RemediationSuggestion;
          enabled?: boolean;
          updated_at?: string;
        };
        Relationships: [];
      };
      audit_logs: {
        Row: {
          id: string;
          user_id: string | null;
          action: string;
          resource_type: string;
          resource_id: string | null;
          metadata: Record<string, unknown>;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id?: string | null;
          action: string;
          resource_type: string;
          resource_id?: string | null;
          metadata?: Record<string, unknown>;
          created_at?: string;
        };
        Update: never;
        Relationships: [];
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
}

export type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];
export type ScanRow = Database["public"]["Tables"]["scans"]["Row"];
export type VulnerabilityRow = Database["public"]["Tables"]["vulnerabilities"]["Row"];
export type AttackSimulationRow = Database["public"]["Tables"]["attack_simulations"]["Row"];
export type SecurityReportRow = Database["public"]["Tables"]["security_reports"]["Row"];
export type CustomRuleRow = Database["public"]["Tables"]["custom_rules"]["Row"];
export type AuditLogRow = Database["public"]["Tables"]["audit_logs"]["Row"];
