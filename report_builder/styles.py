"""Styling and layout helper utilities for TESSERA v3 Academic Project Report.
Replicates the styling, geometry, tables, and typography of WattWise_Project_Report.docx.
"""
import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

# Color Palette matching WattWise
COLOR_PRIMARY = RGBColor(0x3B, 0x0A, 0x7A)    # Deep Royal Purple #3B0A7A
COLOR_SECONDARY = RGBColor(0x1E, 0x29, 0x3B)  # Dark Slate #1E293B
COLOR_MUTED = RGBColor(0x59, 0x59, 0x59)      # Neutral Gray #595959
COLOR_BLACK = RGBColor(0x0F, 0x17, 0x2A)      # Body Dark Text
HEX_PRIMARY = "3B0A7A"
HEX_LIGHT_BG = "F8FAFC"
HEX_WHITE = "FFFFFF"
HEX_BORDER = "CCCCCC"
HEX_INNER_BORDER = "E2E8F0"
HEX_CALLOUT_BG = "F1F5F9"
HEX_CODE_BG = "F8FAFC"

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_table_borders(table, color=HEX_BORDER, inside_color=HEX_INNER_BORDER):
    tblPr = table._tbl.tblPr
    tblBorders = OxmlElement('w:tblBorders')
    for border_name in ['top', 'left', 'bottom', 'right']:
        border = OxmlElement(f'w:{border_name}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '4')
        border.set(qn('w:space'), '0')
        border.set(qn('w:color'), color)
        tblBorders.append(border)
    for border_name in ['insideH', 'insideV']:
        border = OxmlElement(f'w:{border_name}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '4')
        border.set(qn('w:space'), '0')
        border.set(qn('w:color'), inside_color)
        tblBorders.append(border)
    tblPr.append(tblBorders)

def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for side, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        m = OxmlElement(f'w:{side}')
        m.set(qn('w:w'), str(val))
        m.set(qn('w:type'), 'dxa')
        tcMar.append(m)
    tcPr.append(tcMar)

def add_header_row_formatting(row):
    trPr = row._tr.get_or_add_trPr()
    tblHeader = OxmlElement('w:tblHeader')
    cantSplit = OxmlElement('w:cantSplit')
    trPr.append(tblHeader)
    trPr.append(cantSplit)

def create_styled_table(doc, col_widths, headers, data, col_alignments=None):
    num_rows = len(data) + 1
    num_cols = len(headers)
    table = doc.add_table(rows=num_rows, cols=num_cols)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table)
    
    # Header Row
    header_row = table.rows[0]
    add_header_row_formatting(header_row)
    for i, title in enumerate(headers):
        cell = header_row.cells[i]
        cell.width = Inches(col_widths[i])
        set_cell_background(cell, HEX_PRIMARY)
        set_cell_margins(cell, top=130, bottom=130, left=140, right=140)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        align = col_alignments[i] if col_alignments else 'L'
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER if align == 'C' else (WD_ALIGN_PARAGRAPH.RIGHT if align == 'R' else WD_ALIGN_PARAGRAPH.LEFT)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(title)
        run.font.name = 'Arial'
        run.font.size = Pt(9.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    # Data Rows
    for r_idx, row_data in enumerate(data):
        row = table.rows[r_idx + 1]
        trPr = row._tr.get_or_add_trPr()
        trPr.append(OxmlElement('w:cantSplit'))
        bg_color = HEX_LIGHT_BG if (r_idx % 2 == 1) else HEX_WHITE
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.width = Inches(col_widths[c_idx])
            set_cell_background(cell, bg_color)
            set_cell_margins(cell, top=90, bottom=90, left=140, right=140)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            align = col_alignments[c_idx] if col_alignments else 'L'
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if align == 'C' else (WD_ALIGN_PARAGRAPH.RIGHT if align == 'R' else WD_ALIGN_PARAGRAPH.LEFT)
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.15
            run = p.add_run(str(val))
            run.font.name = 'Times New Roman'
            run.font.size = Pt(9.0)
            run.font.color.rgb = COLOR_SECONDARY
            
    return table

format_table = create_styled_table

def add_p(doc, text="", bold_prefix="", space_after=7.0, line_spacing=1.3, italic=False, bold=False):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = line_spacing
    if bold_prefix:
        r_pre = p.add_run(bold_prefix)
        r_pre.font.name = 'Times New Roman'
        r_pre.font.size = Pt(11.0)
        r_pre.font.bold = True
        r_pre.font.color.rgb = COLOR_SECONDARY
    if text:
        r_text = p.add_run(text)
        r_text.font.name = 'Times New Roman'
        r_text.font.size = Pt(11.0)
        r_text.font.italic = italic
        r_text.font.bold = bold
        r_text.font.color.rgb = COLOR_BLACK
    return p

def add_bullet(doc, text="", bold_prefix=""):
    p = doc.add_paragraph(style='List Paragraph')
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(4.0)
    p.paragraph_format.line_spacing = 1.25
    p.paragraph_format.left_indent = Inches(0.25)
    if bold_prefix:
        r_pre = p.add_run(bold_prefix)
        r_pre.font.name = 'Times New Roman'
        r_pre.font.size = Pt(11.0)
        r_pre.font.bold = True
        r_pre.font.color.rgb = COLOR_SECONDARY
    if text:
        r_text = p.add_run(text)
        r_text.font.name = 'Times New Roman'
        r_text.font.size = Pt(11.0)
        r_text.font.color.rgb = COLOR_BLACK
    return p

def add_h1(doc, text):
    p = doc.add_paragraph(text, style='Heading 1')
    p.paragraph_format.space_before = Pt(15.0)
    p.paragraph_format.space_after = Pt(6.0)
    p.paragraph_format.keep_with_next = True
    r = p.runs[0]
    r.font.name = 'Arial'
    r.font.size = Pt(16.0)
    r.font.bold = True
    r.font.color.rgb = COLOR_PRIMARY
    return p

def add_h2(doc, text):
    p = doc.add_paragraph(text, style='Heading 2')
    p.paragraph_format.space_before = Pt(12.0)
    p.paragraph_format.space_after = Pt(4.0)
    p.paragraph_format.keep_with_next = True
    r = p.runs[0]
    r.font.name = 'Arial'
    r.font.size = Pt(13.5)
    r.font.bold = True
    r.font.color.rgb = COLOR_SECONDARY
    return p

def add_h3(doc, text):
    p = doc.add_paragraph(text)
    p.paragraph_format.space_before = Pt(9.0)
    p.paragraph_format.space_after = Pt(3.0)
    p.paragraph_format.keep_with_next = True
    r = p.runs[0]
    r.font.name = 'Arial'
    r.font.size = Pt(11.5)
    r.font.bold = True
    r.font.color.rgb = COLOR_PRIMARY
    return p

def add_callout(doc, text):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    cell.width = Inches(6.27)
    set_cell_background(cell, HEX_CALLOUT_BG)
    set_cell_margins(cell, top=120, bottom=120, left=180, right=150)
    
    tcPr = cell._tc.get_or_add_tcPr()
    tblBorders = OxmlElement('w:tblBorders')
    left = OxmlElement('w:left')
    left.set(qn('w:val'), 'single')
    left.set(qn('w:sz'), '24') # 3pt width
    left.set(qn('w:space'), '0')
    left.set(qn('w:color'), HEX_PRIMARY)
    tblBorders.append(left)
    for b_name in ['top', 'bottom', 'right', 'insideH', 'insideV']:
        b = OxmlElement(f'w:{b_name}')
        b.set(qn('w:val'), 'none')
        tblBorders.append(b)
    tcPr.append(tblBorders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.2
    run = p.add_run(text)
    run.font.name = 'Times New Roman'
    run.font.size = Pt(10.0)
    run.font.italic = True
    run.font.color.rgb = COLOR_SECONDARY
    doc.add_paragraph().paragraph_format.space_after = Pt(3)

def add_equation_box(doc, equation_text, label=""):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    cell.width = Inches(6.27)
    set_cell_background(cell, HEX_CODE_BG)
    set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
    
    # Border
    tcPr = cell._tc.get_or_add_tcPr()
    tblBorders = OxmlElement('w:tblBorders')
    for b_name in ['top', 'bottom', 'left', 'right']:
        b = OxmlElement(f'w:{b_name}')
        b.set(qn('w:val'), 'single')
        b.set(qn('w:sz'), '4')
        b.set(qn('w:space'), '0')
        b.set(qn('w:color'), HEX_INNER_BORDER)
        tblBorders.append(b)
    tcPr.append(tblBorders)
    
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(3)
    run = p.add_run(equation_text)
    run.font.name = 'Cambria Math'
    run.font.size = Pt(10.5)
    run.font.bold = True
    run.font.color.rgb = COLOR_PRIMARY
    
    if label:
        r_lbl = p.add_run(f"    ({label})")
        r_lbl.font.name = 'Times New Roman'
        r_lbl.font.size = Pt(9.5)
        r_lbl.font.color.rgb = COLOR_MUTED
    doc.add_paragraph().paragraph_format.space_after = Pt(3)

def add_figure(doc, image_path, caption_text, width_inches=5.2):
    if not os.path.exists(image_path):
        return
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run()
    run.add_picture(image_path, width=Inches(width_inches))
    
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after = Pt(10)
    r_cap = p_cap.add_run(caption_text)
    r_cap.font.name = 'Times New Roman'
    r_cap.font.size = Pt(9.5)
    r_cap.font.italic = True
    r_cap.font.color.rgb = COLOR_MUTED

def setup_page_layout_and_footer(doc, project_title, course_name):
    sec0 = doc.sections[0]
    sec0.top_margin = Inches(1.0)
    sec0.bottom_margin = Inches(1.0)
    sec0.left_margin = Inches(1.0)
    sec0.right_margin = Inches(1.0)
    sec0.page_width = Inches(8.27)   # A4
    sec0.page_height = Inches(11.69) # A4
    sec0.different_first_page_header_footer = True
    
    footer = sec0.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    topBdr = OxmlElement('w:top')
    topBdr.set(qn('w:val'), 'single')
    topBdr.set(qn('w:sz'), '4')
    topBdr.set(qn('w:space'), '4')
    topBdr.set(qn('w:color'), 'A6A6A6')
    pBdr.append(topBdr)
    pPr.append(pBdr)
    
    r1 = p.add_run(f"{project_title} · {course_name} · Page ")
    r1.font.name = 'Times New Roman'
    r1.font.size = Pt(9.0)
    r1.font.color.rgb = COLOR_MUTED
    
    fldChar1 = OxmlElement('w:fldChar')
    fldChar1.set(qn('w:fldCharType'), 'begin')
    instrText = OxmlElement('w:instrText')
    instrText.set(qn('xml:space'), 'preserve')
    instrText.text = "PAGE"
    fldChar2 = OxmlElement('w:fldChar')
    fldChar2.set(qn('w:fldCharType'), 'separate')
    fldChar3 = OxmlElement('w:fldChar')
    fldChar3.set(qn('w:fldCharType'), 'end')
    
    r_page = p.add_run()
    r_page.font.name = 'Times New Roman'
    r_page.font.size = Pt(9.0)
    r_page.font.color.rgb = COLOR_MUTED
    r_page._r.append(fldChar1)
    r_page._r.append(instrText)
    r_page._r.append(fldChar2)
    r_page._r.append(fldChar3)
