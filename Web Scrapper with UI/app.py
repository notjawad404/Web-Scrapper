from flask import Flask, request, render_template, jsonify, Response
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json

app = Flask(__name__)

def get_page_data(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    data = {
        "url": url,
        "images": [image['src'] if 'src' in image.attrs else '' for image in soup.find_all('img')],
        "paragraphs": [paragraph.text.strip() for paragraph in soup.find_all('p')],
        "tables": [],
        "lists": [],
        "forms": [],
        "options": [],
        "buttons": [button.text.strip() for button in soup.find_all('button')],
        "labels": [label.text.strip() for label in soup.find_all('label')],
        "headings": {f"h{i}": [tag.text.strip() for tag in soup.find_all(f'h{i}')] for i in range(1, 7)},
        "meta_tags": [str(tag) for tag in soup.find_all('meta')],
        "links": []
    }
    
    for link in soup.find_all('a', href=True):
        data["links"].append(link['href'])
    
    for table in soup.find_all('table'):
        table_data = []
        for row in table.find_all('tr'):
            row_data = []
            for cell in row.find_all(['td', 'th']):
                row_data.append(cell.text.strip())
            table_data.append(row_data)
        data["tables"].append(table_data)
    
    for ul in soup.find_all('ul'):
        list_data = [li.text.strip() for li in ul.find_all('li')]
        data["lists"].append(list_data)
    
    for form in soup.find_all('form'):
        form_data = {
            "action": form.get('action'),
            "method": form.get('method'),
            "inputs": [{input_tag.get('name'): input_tag.get('value')} for input_tag in form.find_all('input')]
        }
        data["forms"].append(form_data)
    
    for select in soup.find_all('select'):
        select_data = {
            "name": select.get('name'),
            "options": [option.text.strip() for option in select.find_all('option')]
        }
        data["options"].append(select_data)
    
    return data

def check_malicious_links(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            malicious_links = []
            for link in soup.find_all('a', href=True):
                link_url = link['href']
                if link_url.startswith('http'):
                    try:
                        link_response = requests.get(link_url, timeout=5)
                        if link_response.status_code != 200:
                            malicious_links.append(link_url)
                    except Exception as e:
                        pass
            return malicious_links
    except Exception as e:
        pass
    return []

def crawl(start_url, max_pages):
    visited_urls = set()
    queue = [start_url]
    count = 0
    data = []
    malicious_links = set()

    while queue and count < max_pages:
        url = queue.pop(0)
        if url not in visited_urls:
            page_data = get_page_data(url)
            data.append(page_data)
            count += 1
            visited_urls.add(url)
            
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                next_url = urljoin(start_url, link['href'])
                if next_url.startswith(start_url) and next_url not in visited_urls:
                    queue.append(next_url)

    for url in visited_urls:
        malicious_links.update(check_malicious_links(url))
    
    return {"data": data, "malicious_links": list(malicious_links)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crawl', methods=['GET'])
def start_crawl():
    start_url = request.args.get('url')
    max_pages = int(request.args.get('max_pages'))
    
    def generate():
        yield 'data: {"crawled_pages": 0}\n\n'
        yield 'data: {"status": "Crawling in progress..."}\n\n'
        count = 0
        for page in crawl(start_url, max_pages)["data"]:
            count += 1
            yield f'data: {json.dumps({"crawled_pages": count, "page": page})}\n\n'

    return Response(generate(), content_type='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)
