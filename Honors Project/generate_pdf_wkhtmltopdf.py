import os
import markdown
import pdfkit

# Configuration
WKHTMLTOPDF_PATH = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
INPUT_FILE = 'SUBMISSION_CONTENT.md'
OUTPUT_FILE = 'Submission_Final.pdf'
BASE_DIR = os.getcwd()

def convert():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found")
        return

    print(f"Reading {INPUT_FILE}...")
    # 1. Read Markdown
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        text = f.read()

    # 2. Convert to HTML
    # 'fenced_code' for ``` blocks
    # 'tables' for tables
    html_content = markdown.markdown(text, extensions=['extra', 'codehilite', 'fenced_code', 'tables'])

    # 3. CSS for GitHub-like styling
    css = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; 
            line-height: 1.6; 
            padding: 2em; 
            max-width: 900px; 
            margin: 0 auto; 
            color: #24292e;
        }
        h1, h2, h3, h4, h5, h6 {
            margin-top: 24px;
            margin-bottom: 16px;
            font-weight: 600;
            line-height: 1.25;
        }
        h1 { font-size: 2em; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
        h2 { font-size: 1.5em; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
        p { margin-top: 0; margin-bottom: 16px; }
        
        /* Code Blocks */
        pre { 
            background-color: #f6f8fa; 
            padding: 16px; 
            border-radius: 6px; 
            overflow: auto; 
            white-space: pre-wrap; /* Key for wrapping */
            word-wrap: break-word; 
            font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 85%;
            line-height: 1.45;
        }
        code { 
            font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace; 
            background-color: rgba(27,31,35,0.05); 
            padding: 0.2em 0.4em; 
            border-radius: 3px; 
            font-size: 85%;
        }
        pre code { 
            background-color: transparent; 
            padding: 0; 
            font-size: 100%;
            white-space: pre-wrap;
        }
        
        /* Images */
        img { 
            max-width: 100%; 
            box-sizing: content-box; 
            background-color: #fff; 
            border: 1px solid #eee;
        }
        
        /* Tables */
        table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
        th, td { border: 1px solid #dfe2e5; padding: 6px 13px; }
        tr:nth-child(2n) { background-color: #f6f8fa; }
        
        blockquote { border-left: 0.25em solid #dfe2e5; color: #6a737d; padding: 0 1em; }
    </style>
    """
    
    # 4. Construct Full HTML with Base URL for images
    # The <base> tag tells wkhtmltopdf where to look for relative images
    # We use file:/// URI scheme
    base_url = 'file:///' + BASE_DIR.replace('\\', '/') + '/'
    
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <base href="{base_url}">
        {css}
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    # 5. Convert to PDF
    try:
        config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
        options = {
            "enable-local-file-access": "",
            "encoding": "UTF-8",
            "no-outline": None,
            "page-size": "A4",
            "margin-top": "20mm",
            "margin-right": "20mm",
            "margin-bottom": "20mm",
            "margin-left": "20mm",
        }
        
        print("Generating PDF with wkhtmltopdf...")
        pdfkit.from_string(full_html, OUTPUT_FILE, configuration=config, options=options)
        print(f"Success! Saved to {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    convert()
