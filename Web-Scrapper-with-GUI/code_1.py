import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
import json


def get_page_data(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    data = {
        "url": url,
        "images": [image['src'] for image in soup.find_all('img')],
        "paragraphs": [paragraph.text.strip() for paragraph in soup.find_all('p')],
        "tables": [],
        "lists": [],
        "forms": [],
        "options": [],
        "buttons": [button.text.strip() for button in soup.find_all('button')],
        "labels": [label.text.strip() for label in soup.find_all('label')],
        "headings": {f"h{i}": [tag.text.strip() for tag in soup.find_all(f'h{i}')] for i in range(1, 6)},
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
    # Create the directory if it doesn't exist
    if not os.path.exists('web_data'):
        os.makedirs('web_data')

    visited_urls = set()
    queue = [start_url]
    count = 0
    malicious_links = []

    while queue and count < max_pages:
        url = queue.pop(0)
        if url not in visited_urls:
            page_data = get_page_data(url)
            with open(f'web_data/page{count+1}.json', 'w', encoding='utf-8') as file:
                json.dump(page_data, file, ensure_ascii=False, indent=4)
            count += 1
            visited_urls.add(url)

            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                next_url = urljoin(start_url, link['href'])
                if next_url.startswith(start_url) and next_url not in visited_urls:
                    queue.append(next_url)

    for url in visited_urls:
        malicious_links.extend(check_malicious_links(url))
    
    with open("malicious_links.json", "w") as json_file:
        json.dump(malicious_links, json_file, indent=4)

    return {
        "crawled_pages": count,
        "malicious_links": malicious_links
    }

class WebCrawlerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Web Crawler")
        self.root.geometry("1900x1080")
        self.create_widgets()

    def create_widgets(self):
        self.start_label = ttk.Label(self.root, text="Enter the start URL:")
        self.start_label.pack(pady=5)
        self.start_entry = ttk.Entry(self.root, width=40)
        self.start_entry.pack(pady=5)

        self.max_label = ttk.Label(self.root, text="Enter the maximum number of pages to crawl:")
        self.max_label.pack(pady=5)
        self.max_entry = ttk.Entry(self.root, width=10)
        self.max_entry.pack(pady=5)

        self.start_button = ttk.Button(self.root, text="Start Crawling", command=self.start_crawling)
        self.start_button.pack(pady=10)

    def start_crawling(self):
        start_url = self.start_entry.get()
        max_pages = int(self.max_entry.get())

        if start_url == "" or max_pages == "":
            messagebox.showerror("Error", "Please enter start URL and maximum number of pages to crawl.")
            return

        result = crawl(start_url, max_pages)
        messagebox.showinfo("Crawling Result", f"Crawled {result['crawled_pages']} pages.\nFound {len(result['malicious_links'])} malicious links.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    import sys
    if 'idlelib.run' in sys.modules:
        app = WebCrawlerApp()
        app.run()
    else:
        try:
            app = WebCrawlerApp()
            app.run()
        except tk.TclError:
            print("Unable to open Tkinter window. No display name and no $DISPLAY environment variable.")
