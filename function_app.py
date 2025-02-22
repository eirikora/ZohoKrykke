import azure.functions as func
import logging
import re
import os
import tempfile
import json
import base64
import mammoth
from bs4 import BeautifulSoup
import quopri
from docx import Document

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="http_test")
def http_test(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
    

def decode_mime_string(s):
    if '=' in s:
        start = s.find('=')
        prefix = s[:start]
        #print(prefix)
        mimestring = s[start:]
        #print(mimestring)
        mime_elements = mimestring.split('=_=')
        #print(mime_elements)
        decoded_text = ''
        for submime in mime_elements:
            charset, encoded_text = submime.strip('=_').strip('_=').split('_Q_', 1)
            #decoded_text += quopri.decodestring(encoded_text.replace('_', '=')).decode(charset).replace('=', ' ')
            decoded_text += quopri.decodestring(encoded_text).decode(charset)
        return prefix + decoded_text
    else:
        return s


@app.route(route="MimeDecode", auth_level=func.AuthLevel.ANONYMOUS)
def MimeDecode(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('MimeDecode trigger function processed a request.')

    mime_string = req.params.get('mime_string')
    if not mime_string:
        try:
            req_body = req.get_json()
        except ValueError:
            mime_string = str(req.get_body(), 'utf-8')
        else:
            mime_string = req_body.get('mime_string')

    if mime_string:
        decoded_string = decode_mime_string(mime_string) # Now also handles prefixed mime-strings
        return func.HttpResponse(decoded_string, mimetype="text/plain;charset=UTF-8", status_code=200)
    else:
        return func.HttpResponse(
             "Please pass a mime_string on the query string or in the request body",
             status_code=400
        )
    
def allowed_file(filename):
    logging.info("Checking "+ filename)
    ALLOWED_EXTENSIONS = {'doc', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_header_footer(docx_path):
    # Load the document using python-docx
    doc = Document(docx_path)

    # Extract header text
    header_text = []
    for section in doc.sections:
        for header in section.header.paragraphs:
            header_text.append(header.text)

    # Extract footer text
    footer_text = []
    for section in doc.sections:
        for footer in section.footer.paragraphs:
            footer_text.append(footer.text)

    return "\n".join(header_text + footer_text)

@app.route(route="Word2Text", auth_level=func.AuthLevel.ANONYMOUS)
def Word2Text(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Word2Text trigger function processed a request.')

    file_content = b''
    file_name = ''
    if 'content' not in req.files:
        try:
            logging.info('Getting the body...')
            req_body = req.get_body()
            json_data = json.loads(req_body, strict=False)
            encoded_content = json_data["parameters"]["body"]["$content"]
            # Decode the content
            file_content = base64.b64decode(encoded_content)
            file_name = "powerapp.docx"
        except ValueError:
            logging.info('ERROR: No file part in the request.')
            #file_content = req.get_body()
            return func.HttpResponse('ERROR: No file part in the request', mimetype="text/plain;charset=UTF-8", status_code=400)
        #return 'No file part in the request', 400
        #return func.HttpResponse(str(req_body[0:100]), mimetype="text/plain;charset=UTF-8", status_code=400)
    else:
        file = req.files['content']
        file_content = file.read()
        file_name = file.filename

    # Expect a Word filename to attempt convert
    if allowed_file(file_name):
        logging.info('Converting file ' + file_name)
        # Write the binary data to a temp Word file
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix=".docx") as f:
            f.write(file_content)
            temp_filename = f.name
        
        # Get the header and footer from the file
        headerfooter = extract_header_footer(temp_filename)

        # Read and convert temp Word file into HTML for analysis
        with open(temp_filename, "rb") as docx_file:
            try:
                result = mammoth.convert_to_html(docx_file)
                html = result.value
            except Exception as e:
                html = "<p>Word2Text ERROR: Document was not a Microsoft Word document in .docx format (Zip file) that could be analyzed.</p>\n"
                # hex_representation = file_content[0:200].hex()
                # hex_representation_spaced = ' '.join(hex_representation[i:i+2] for i in range(0, len(hex_representation), 2))
                # html = html + "<p>" + hex_representation_spaced + "</p>\n"
                # html = html + "<p>" + str(req_body)[2:40] + "</p>\n"
        # Delete temp file
        try:
            os.remove(temp_filename)
        except OSError:
            pass
        
        # Create a BeautifulSoup object
        soup = BeautifulSoup(html, 'html.parser')

        plain_text = soup.get_text(separator='\n')
        plain_text = "HEADER_FOOTER:\n" + headerfooter + '\nFRONT_PAGE:\n' + plain_text
        plain_text = re.sub('\t',' ',plain_text)
        # Return the resultset
        return func.HttpResponse(plain_text, mimetype="text/plain;charset=UTF-8", status_code=200)
    else:
        logging.info('ERROR: Did not find a Word document to convert in request body!')
        return func.HttpResponse(
             "ERROR: Could not find a file in doc/docx format that we can convert. File received was: " + file_name,
             status_code=400
        )