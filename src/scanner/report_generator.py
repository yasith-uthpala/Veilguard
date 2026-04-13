import json
import os
from datetime import datetime
from pathlib import Path
from fpdf import FPDF
from rich.console import Console

console = Console()


class ReportGenerator:
    """Generate PDF and JSON reports from scan results"""
    
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.reports_dir = Path(__file__).parent.parent.parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    def export_json(self, results: list, geoip_data: dict = None) -> str:
        """Export scan results as JSON"""
        report_data = {
            "metadata": {
                "target": self.target,
                "scan_time": datetime.now().isoformat(),
                "total_ports": len(results),
                "vulnerable_ports": sum(1 for r in results if r.get("is_vulnerable"))
            },
            "geolocation": geoip_data or {},
            "results": []
        }
        
        # Transform results for JSON export
        for result in results:
            port_data = {
                "port": result.get("port"),
                "protocol": result.get("proto"),
                "state": result.get("state"),
                "service": result.get("service"),
                "product": result.get("product"),
                "is_vulnerable": result.get("is_vulnerable"),
                "risk": result.get("risk"),
                "vulnerability_reason": result.get("vuln_reason"),
                "country": result.get("country"),
                "city": result.get("city"),
                "isp": result.get("isp"),
                "scanned_at": result.get("scanned_at"),
            }
            
            # Add CVE information if available
            if result.get("cves"):
                port_data["cves"] = [
                    {
                        "id": cve.get("cve_id"),
                        "cvss_score": cve.get("cvss_score"),
                        "description": cve.get("description"),
                        "published": cve.get("published"),
                        "url": cve.get("url")
                    }
                    for cve in result.get("cves", [])
                ]
            
            report_data["results"].append(port_data)
        
        # Save JSON file
        json_file = self.reports_dir / f"scan_{self.target.replace('.', '_')}_{self.timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(report_data, f, indent=2)
        
        console.print(f"[green]✅ JSON report saved: {json_file}[/green]")
        return str(json_file)
    
    def export_pdf(self, results: list, geoip_data: dict = None) -> str:
        """Generate professional PDF report"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24)
        
        # Title
        pdf.cell(0, 10, "Veilguard Security Scan Report", ln=True, align="C")
        
        pdf.set_font("Helvetica", "", 11)
        pdf.ln(5)
        
        # Metadata
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Scan Information", ln=True)
        pdf.set_font("Helvetica", "", 10)
        
        pdf.cell(50, 6, "Target:", ln=False)
        pdf.cell(0, 6, str(self.target), ln=True)
        
        pdf.cell(50, 6, "Scan Time:", ln=False)
        pdf.cell(0, 6, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ln=True)
        
        pdf.cell(50, 6, "Total Ports:", ln=False)
        pdf.cell(0, 6, str(len(results)), ln=True)
        
        vulnerable_count = sum(1 for r in results if r.get("is_vulnerable"))
        pdf.cell(50, 6, "Vulnerable:", ln=False)
        pdf.cell(0, 6, str(vulnerable_count), ln=True)
        
        # Geolocation info
        if geoip_data and "error" not in geoip_data:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Geolocation Information", ln=True)
            pdf.set_font("Helvetica", "", 10)
            
            if not geoip_data.get("is_private"):
                pdf.cell(50, 6, "Country:", ln=False)
                pdf.cell(0, 6, f"{geoip_data.get('country')} ({geoip_data.get('country_code')})", ln=True)
                
                pdf.cell(50, 6, "City:", ln=False)
                pdf.cell(0, 6, geoip_data.get('city', 'N/A'), ln=True)
                
                pdf.cell(50, 6, "ISP:", ln=False)
                pdf.cell(0, 6, geoip_data.get('isp', 'N/A'), ln=True)
                
                if geoip_data.get("is_high_risk"):
                    pdf.set_text_color(255, 0, 0)
                    pdf.cell(50, 6, "High Risk:", ln=False)
                    pdf.cell(0, 6, "Yes - Suspicious Country", ln=True)
                    pdf.set_text_color(0, 0, 0)
        
        # Risk Summary
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Risk Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        
        risk_counts = {}
        for r in results:
            risk = r.get("risk", "OK")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK"]
        for risk in risk_order:
            if risk in risk_counts:
                count = risk_counts[risk]
                if risk == "CRITICAL":
                    pdf.set_text_color(255, 0, 0)
                elif risk == "HIGH":
                    pdf.set_text_color(200, 0, 0)
                elif risk == "MEDIUM":
                    pdf.set_text_color(255, 165, 0)
                else:
                    pdf.set_text_color(0, 100, 0)
                
                pdf.cell(50, 6, f"{risk}:", ln=False)
                pdf.cell(0, 6, str(count), ln=True)
                pdf.set_text_color(0, 0, 0)
        
        # Port Details Table
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Open Ports", ln=True)
        pdf.set_font("Helvetica", "", 9)
        
        # Table header
        pdf.set_fill_color(200, 200, 200)
        pdf.cell(15, 7, "Port", 1, 0, "C", True)
        pdf.cell(20, 7, "Risk", 1, 0, "C", True)
        pdf.cell(30, 7, "Service", 1, 0, "C", True)
        pdf.cell(60, 7, "Product", 1, 0, "L", True)
        pdf.cell(40, 7, "Country", 1, 1, "C", True)
        
        # Table rows
        for result in sorted(results, key=lambda x: x.get("risk", "OK")):
            port = result.get("port")
            risk = result.get("risk", "OK")
            service = result.get("service", "unknown")[:20]
            product = result.get("product", "")[:50]
            country = result.get("country", "N/A")[:15]
            
            # Set row background color based on risk
            if risk == "CRITICAL":
                pdf.set_fill_color(255, 200, 200)
            elif risk == "HIGH":
                pdf.set_fill_color(255, 220, 200)
            elif risk == "MEDIUM":
                pdf.set_fill_color(255, 240, 200)
            else:
                pdf.set_fill_color(240, 255, 240)
            
            pdf.cell(15, 6, str(port), 1, 0, "C", True)
            pdf.cell(20, 6, risk, 1, 0, "C", True)
            pdf.cell(30, 6, service, 1, 0, "L", True)
            pdf.cell(60, 6, product, 1, 0, "L", True)
            pdf.cell(40, 6, country, 1, 1, "L", True)
        
        # Recommendations
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Recommendations", ln=True)
        pdf.set_font("Helvetica", "", 10)
        
        recommendations = [
            "1. Close unnecessary ports using firewall rules",
            "2. Update all software to latest security patches",
            "3. Use strong authentication (SSH keys, strong passwords)",
            "4. Monitor high-risk countries for suspicious access",
            "5. Enable logging and alerting for all ports",
            "6. Conduct regular security scans (weekly or monthly)",
            "7. Review and address all CRITICAL risk ports immediately"
        ]
        
        for rec in recommendations:
            pdf.cell(0, 5, rec, ln=True)
        
        # Save PDF file
        pdf_file = self.reports_dir / f"scan_{self.target.replace('.', '_')}_{self.timestamp}.pdf"
        pdf.output(str(pdf_file))
        
        console.print(f"[green]✅ PDF report saved: {pdf_file}[/green]")
        return str(pdf_file)
    
    def export_both(self, results: list, geoip_data: dict = None) -> tuple:
        """Export both JSON and PDF reports"""
        json_file = self.export_json(results, geoip_data)
        pdf_file = self.export_pdf(results, geoip_data)
        return json_file, pdf_file
