"""
Bulk CSV Email Lead Cleaner using DataShield SDK
Reads a dirty leads CSV, verifies email hygiene, filters burner domains, and exports a clean CSV.
"""

import csv
import sys
from datashield import DataShieldClient

def clean_csv(input_csv: str, output_csv: str, api_key: str):
    client = DataShieldClient(api_key=api_key)
    print(f"[*] Processing lead database: {input_csv}")

    total = 0
    clean = 0
    burned = 0

    with open(input_csv, mode="r", encoding="utf-8") as fin, \
         open(output_csv, mode="w", newline="", encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames or ["email"]
        new_fields = fieldnames + ["is_valid", "is_disposable", "verdict", "risk_score"]

        writer = csv.DictWriter(fout, fieldnames=new_fields)
        writer.writeheader()

        for row in reader:
            total += 1
            email = row.get("email", "").strip()
            if not email:
                continue

            try:
                res = client.validate_email(email)
                row["is_valid"] = "1" if res.is_valid_format else "0"
                row["is_disposable"] = "1" if res.is_disposable else "0"
                row["verdict"] = res.verdict
                row["risk_score"] = res.risk_score

                if not res.is_disposable and res.mx_records_found:
                    clean += 1
                else:
                    burned += 1

                writer.writerow(row)
                print(f"[{total}] {email} -> {res.verdict} (Risk: {res.risk_score})")

            except Exception as e:
                print(f"[!] Error validating {email}: {e}")

    print("\n[+] Verification Complete!")
    print(f"    Total Checked: {total}")
    print(f"    Deliverable:   {clean} ({(clean/total*100):.1f}%)" if total else 0)
    print(f"    Burned/Fake:   {burned} ({(burned/total*100):.1f}%)" if total else 0)
    print(f"    Clean Leads Exported To: {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python bulk_csv_cleaner.py <input.csv> <output.csv> <RAPIDAPI_KEY>")
        sys.exit(1)
    clean_csv(sys.argv[1], sys.argv[2], sys.argv[3])
