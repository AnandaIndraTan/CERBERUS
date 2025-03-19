from fpdf import FPDF
from datetime import datetime
import textwrap

class VulnerabilityReport:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.sections = []  # Initialize sections list

    def add_cover_page(self):
        self.pdf.add_page()
        # Red background
        self.pdf.set_fill_color(180, 0, 0)
        self.pdf.rect(0, 0, 210, 297, 'F')
        
        # White text
        self.pdf.set_text_color(255, 255, 255)
        
        # Company name
        self.pdf.set_font("Arial", "B", 24)
        self.pdf.ln(60)
        self.pdf.cell(0, 20, "CERBERUS", ln=True, align='C')
        
        # Report title
        self.pdf.set_font("Arial", "B", 28)
        self.pdf.ln(20)
        self.pdf.cell(0, 20, "Security Assessment", ln=True, align='C')
        self.pdf.cell(0, 20, "Report", ln=True, align='C')
        
        # Date and Report ID
        self.pdf.set_font("Arial", "", 12)
        self.pdf.ln(40)
        self.pdf.cell(0, 10, f"Date: {datetime.now().strftime('%B %d, %Y')}", ln=True, align='C')
        self.pdf.cell(0, 10, f"Report ID: CERB-{datetime.now().strftime('%Y%m%d')}-001", ln=True, align='C')
        
        # Reset text color
        self.pdf.set_text_color(0, 0, 0)

    def add_table_of_contents(self):
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 18)
        self.pdf.cell(0, 15, "Table of Contents", ln=True)
        self.pdf.ln(10)
        
        self.pdf.set_font("Arial", "", 12)
        current_page = 2  # Start from page 2 (after cover)
        
        # Calculate available width
        page_width = self.pdf.w - self.pdf.l_margin - self.pdf.r_margin
        
        for section in self.sections:
            page_number_width = self.pdf.get_string_width(str(current_page))
            
            if not section.startswith('   '):  # Main sections
                self.pdf.set_font("Arial", "B", 12)
                
                # Limit title width to prevent overflow
                title = section
                max_title_width = page_width * 0.7  # Use at most 70% of page width for title
                title_width = self.pdf.get_string_width(title)
                
                if title_width > max_title_width:
                    # Truncate and add ellipsis
                    while title and self.pdf.get_string_width(title + "...") > max_title_width:
                        title = title[:-1]
                    title += "..."
                    title_width = self.pdf.get_string_width(title)
                
                dots_width = page_width - title_width - page_number_width - 5
                num_dots = int(dots_width / self.pdf.get_string_width('.'))
                
                if num_dots > 0:  # Ensure we have space for dots
                    self.pdf.cell(title_width, 10, title, ln=0)
                    self.pdf.cell(dots_width, 10, '.' * num_dots, ln=0, align='R')
                    self.pdf.cell(page_number_width + 5, 10, str(current_page), ln=True, align='R')
                else:
                    # Not enough space for dots, just show title and page number
                    self.pdf.cell(page_width - page_number_width - 5, 10, title, ln=0)
                    self.pdf.cell(page_number_width + 5, 10, str(current_page), ln=True, align='R')
                
            else:  # Subsections
                self.pdf.set_font("Arial", "", 12)
                indent_width = 20
                title = section.strip()  # Remove leading spaces
                
                # Limit title width to prevent overflow
                max_title_width = page_width * 0.6  # Use at most 60% of page width for subsection title
                title_width = self.pdf.get_string_width(title)
                
                if title_width > max_title_width:
                    # Truncate and add ellipsis
                    while title and self.pdf.get_string_width(title + "...") > max_title_width:
                        title = title[:-1]
                    title += "..."
                    title_width = self.pdf.get_string_width(title)
                
                dots_width = page_width - title_width - page_number_width - indent_width - 5
                num_dots = int(dots_width / self.pdf.get_string_width('.'))
                
                if num_dots > 0:  # Ensure we have space for dots
                    self.pdf.cell(indent_width, 10, "", ln=0)  # Indentation
                    self.pdf.cell(title_width, 10, title, ln=0)
                    self.pdf.cell(dots_width, 10, '.' * num_dots, ln=0, align='R')
                    self.pdf.cell(page_number_width + 5, 10, str(current_page), ln=True, align='R')
                else:
                    # Not enough space for dots, just show title and page number
                    self.pdf.cell(indent_width, 10, "", ln=0)  # Indentation
                    self.pdf.cell(page_width - indent_width - page_number_width - 5, 10, title, ln=0)
                    self.pdf.cell(page_number_width + 5, 10, str(current_page), ln=True, align='R')
                
            current_page += 1
        

    def add_section_page(self, title):
        self.pdf.add_page()
        self.pdf.set_fill_color(180, 0, 0)
        self.pdf.set_text_color(255, 255, 255)
        
        # Add red header banner
        self.pdf.rect(0, 0, 210, 30, 'F')
        
        # Add section title with wrapping for long titles
        self.pdf.set_font("Arial", "B", 24)
        self.pdf.ln(10)
        
        # Calculate available width
        page_width = self.pdf.w - self.pdf.l_margin - self.pdf.r_margin
        
        # Wrap title if needed
        wrapped_lines = textwrap.wrap(title, width=int(page_width/3))  # More conservative width for large font
        
        if len(wrapped_lines) == 1:
            # Single line title
            self.pdf.cell(0, 10, title, ln=True, align='C')
        else:
            # Multi-line title
            for i, wrapped_line in enumerate(wrapped_lines):
                # Use smaller font for subsequent lines if needed
                if i > 0 and len(wrapped_lines) > 2:
                    self.pdf.set_font("Arial", "B", 20)
                self.pdf.cell(0, 8, wrapped_line, ln=True, align='C')
        
        # Reset colors and add less spacing
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.ln(10)

    def format_bold_text(self, text):
        # This method isn't actually used in the code but we'll fix it anyway
        # Calculate available width
        page_width = self.pdf.w - self.pdf.l_margin - self.pdf.r_margin
        
        parts = text.split('**')
        is_bold = False
        
        current_line = ""
        line_width = 0
        
        for part in parts:
            if not part:  # Skip empty parts
                is_bold = not is_bold
                continue
                
            if is_bold:
                self.pdf.set_font("Arial", "B", 11)
            else:
                self.pdf.set_font("Arial", "", 11)
                
            # Check if adding this part would exceed page width
            part_width = self.pdf.get_string_width(part)
            
            if line_width + part_width > page_width:
                # Write current line and start a new one
                self.pdf.cell(0, 6, current_line, ln=True)
                current_line = part
                line_width = part_width
            else:
                current_line += part
                line_width += part_width
                
            is_bold = not is_bold
        
        # Write any remaining text
        if current_line:
            self.pdf.cell(0, 6, current_line, ln=True)
        
        # Reset font to normal
        self.pdf.set_font("Arial", "", 11)

    def add_section_content(self, content, is_subsection=False):
        if not content.strip():
            return
                
        self.pdf.set_font("Arial", size=11)
        
        # Calculate available width
        page_width = self.pdf.w - self.pdf.l_margin - self.pdf.r_margin
        
        lines = content.split('\n')
        for line in lines:
            if line.strip():
                if line.strip().startswith('- '):
                    # For bullet points
                    bullet_indent = 10
                    available_width = page_width - bullet_indent
                    self.pdf.cell(bullet_indent, 6, "-", ln=0)
                    
                    # Clean the text
                    formatted_line = line.strip()[2:]
                    formatted_line = formatted_line.replace('**', '')
                    
                    # Wrap text to fit within available width
                    wrapped_lines = textwrap.wrap(formatted_line, width=int(available_width/2))
                    if wrapped_lines:
                        self.pdf.cell(0, 6, wrapped_lines[0], ln=True)
                        
                        # Handle additional wrapped lines with proper indentation
                        for wrapped_line in wrapped_lines[1:]:
                            self.pdf.cell(bullet_indent, 6, "", ln=0)  # Just indent
                            self.pdf.cell(0, 6, wrapped_line, ln=True)
                    else:
                        self.pdf.cell(0, 6, "", ln=True)
                else:
                    # Regular text
                    cleaned_line = line.strip().replace('**', '')
                    
                    # Use proper text wrapping
                    wrapped_lines = textwrap.wrap(cleaned_line, width=int(page_width/2))
                    for i, wrapped_line in enumerate(wrapped_lines):
                        self.pdf.cell(0, 6, wrapped_line, ln=True)
        
        self.pdf.ln(3)

    def add_subsection_header(self, title):
        if not title.strip():
            return
            
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.ln(3)
        
        # Calculate available width and wrap text if needed
        page_width = self.pdf.w - self.pdf.l_margin - self.pdf.r_margin
        wrapped_lines = textwrap.wrap(title, width=int(page_width/2))
        
        for wrapped_line in wrapped_lines:
            self.pdf.cell(0, 8, wrapped_line, ln=True)
        
        self.pdf.ln(3)

    def parse_markdown_section(self, text):
        sections = {}
        self.sections = []  # Reset sections list
        current_main_section = None
        current_subsection = None
        current_content = []
        
        for line in text.split('\n'):
            if line.startswith('#### '):
                
                if current_main_section:
                    if current_subsection:
                        sections[current_main_section]['subsections'][current_subsection] = '\n'.join(current_content).strip()
                    else:
                        sections[current_main_section]['content'] = '\n'.join(current_content).strip()
                current_main_section = line.replace('#### ', '').strip()
                self.sections.append(current_main_section)  # Add to TOC
                current_subsection = None
                current_content = []
                sections[current_main_section] = {'content': '', 'subsections': {}}
                
            elif line.startswith('##### '):
                
                if current_content and current_main_section:
                    if current_subsection:
                        sections[current_main_section]['subsections'][current_subsection] = '\n'.join(current_content).strip()
                    else:
                        sections[current_main_section]['content'] = '\n'.join(current_content).strip()
                current_subsection = line.replace('##### ', '').strip()
                self.sections.append('   ' + current_subsection)  # Add to TOC with indentation
                current_content = []
                
            else:
                if line.strip():
                    current_content.append(line)
        
        # Handle the last section
        if current_main_section:
            if current_subsection:
                sections[current_main_section]['subsections'][current_subsection] = '\n'.join(current_content).strip()
            else:
                sections[current_main_section]['content'] = '\n'.join(current_content).strip()
        
        return sections

    def generate_report(self, markdown_text, output_folder=None):        
        self.add_cover_page()
        sections = self.parse_markdown_section(markdown_text)
        
        self.add_table_of_contents()
        
        for main_title, section_data in sections.items():
            self.add_section_page(main_title)
            
            if section_data['content'].strip():
                self.add_section_content(section_data['content'])
            
            for sub_title, sub_content in section_data['subsections'].items():
                if sub_title.strip():
                    self.add_subsection_header(sub_title)
                    if sub_content.strip():
                        self.add_section_content(sub_content, is_subsection=True)
        
        # Generate filename with timestamp
        filename = f"cerberus_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Determine the full path based on whether output_folder was provided
        if output_folder:
            import os
            
            # Create the directory if it doesn't exist
            os.makedirs(output_folder, exist_ok=True)
            
            # Construct the full path
            full_path = os.path.join(output_folder, filename)
        else:
            full_path = filename
        
        print(f"\nSaving PDF as: {full_path}")
        self.pdf.output(full_path)
        return full_path