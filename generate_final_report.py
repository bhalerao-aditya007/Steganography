"""Main orchestration script to generate the complete academic project report for TESSERA v3.
Replicates the formatting, depth, and academic structure of WattWise_Project_Report.docx.
Includes Atharv Deshmukh (BT24CSD004), Aditya Bhalerao (BT24CSD018), and Aryan Karmore (BT24CSD009).
"""
import os
import sys
import docx

from report_builder.styles import setup_page_layout_and_footer
from report_builder.sec1_intro import (
    build_cover_page, build_acknowledgements, build_table_of_contents,
    build_chapter_1, build_chapter_2
)
from report_builder.sec2_lit_curric import build_chapter_3, build_chapter_4
from report_builder.sec3_math_crypto import build_chapter_5
from report_builder.sec4_arch_network import build_chapter_6
from report_builder.sec5_implementation import build_chapter_7
from report_builder.sec6_results import build_chapter_8
from report_builder.sec7_impact_future import build_chapter_9, build_chapter_10
from report_builder.sec8_contrib_refs import build_chapter_11, build_chapter_12

def main():
    print("=" * 70)
    print("       TESSERA v3: ACADEMIC PROJECT REPORT GENERATION ENGINE        ")
    print("=" * 70)
    
    doc = docx.Document()
    
    # Configure A4 page layout and dynamic running footer
    print("[1/10] Setting up A4 page geometry, margins, and running footer...")
    setup_page_layout_and_footer(doc, "TESSERA v3: Mirage", "Data Privacy & Security Mini Project")
    
    # Cover Page, Acknowledgements, TOC
    print("[2/10] Generating Cover Page, Acknowledgements, and Table of Contents...")
    build_cover_page(doc)
    build_acknowledgements(doc)
    build_table_of_contents(doc)
    
    # Chapter 1 & Chapter 2
    print("[3/10] Generating Chapter 1 (Abstract) and Chapter 2 (Problem Statement)...")
    build_chapter_1(doc)
    build_chapter_2(doc)
    
    # Chapter 3 & Chapter 4
    print("[4/10] Generating Chapter 3 (Literature Review) and Chapter 4 (Curriculum Mapping)...")
    build_chapter_3(doc)
    build_chapter_4(doc)
    
    # Chapter 5
    print("[5/10] Generating Chapter 5 (Mathematical Formulation, Lemma 1 & Crypto)...")
    build_chapter_5(doc)
    
    # Chapter 6
    print("[6/10] Generating Chapter 6 (System Architecture & Network Workflow)...")
    build_chapter_6(doc)
    
    # Chapter 7
    print("[7/10] Generating Chapter 7 (Implementation & Key Technical Modules)...")
    build_chapter_7(doc)
    
    # Chapter 8
    print("[8/10] Generating Chapter 8 (Testing, Verification & Experimental Results)...")
    build_chapter_8(doc)
    
    # Chapter 9 & Chapter 10
    print("[9/10] Generating Chapter 9 (Real-World Applications) and Chapter 10 (Honest Claims Ledger)...")
    build_chapter_9(doc)
    build_chapter_10(doc)
    
    # Chapter 11 & Chapter 12
    print("[10/10] Generating Chapter 11 (Individual Contributions & Declarations) and References...")
    build_chapter_11(doc)
    build_chapter_12(doc)
    
    # Save outputs
    out_dir_local = os.path.dirname(os.path.abspath(__file__))
    out_path_local = os.path.join(out_dir_local, "TESSERA_v3_Project_Report.docx")
    out_path_parent = os.path.abspath(os.path.join(out_dir_local, "..", "TESSERA_v3_Project_Report.docx"))
    
    doc.save(out_path_local)
    print(f"\n[SUCCESS] Saved primary report to:\n  -> {out_path_local}")
    
    try:
        doc.save(out_path_parent)
        print(f"[SUCCESS] Saved secondary mirror report to:\n  -> {out_path_parent}")
    except Exception as e:
        print(f"[WARNING] Could not save mirror copy: {e}")
        
    # Statistical verification
    total_words = sum(len(p.text.split()) for p in doc.paragraphs)
    for t in doc.tables:
        for row in t.rows:
            for cell in row.cells:
                total_words += len(cell.text.split())
                
    print("\n" + "=" * 70)
    print(f"REPORT GENERATION SUMMARY:")
    print(f"  - Total Document Paragraphs: {len(doc.paragraphs)}")
    print(f"  - Total Structured Tables:   {len(doc.tables)}")
    print(f"  - Total Word Count:          {total_words} words")
    print("=" * 70)

if __name__ == "__main__":
    main()
