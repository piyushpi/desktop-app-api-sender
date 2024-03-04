import sys
import shlex
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QScrollArea, QSizePolicy, QLabel, QListWidget, QListWidgetItem
from PySide6.QtCore import Qt, QThread, Signal
import requests
import json


class APIClient(QWidget):
    def __init__(self):
        super().__init__()

        self.saved_requests = []
        self.saved_responses = []  # Initialize list to store responses
        self.init_ui()
        self.worker = Worker()
        self.worker.text_updated.connect(self.update_text)


    def init_ui(self):
        layout = QHBoxLayout()

        # Left sidebar for saved requests
        self.sidebar_layout = QVBoxLayout()
        self.saved_requests_label = QLabel("Saved Requests:")
        self.sidebar_layout.addWidget(self.saved_requests_label)
        self.saved_requests_list = QListWidget()
        self.saved_requests_list.itemClicked.connect(self.load_saved_request)
        self.sidebar_layout.addWidget(self.saved_requests_list)
        layout.addLayout(self.sidebar_layout)

        # Main layout for input and output
        main_layout = QVBoxLayout()

        # Paste cURL command
        self.curl_input_label = QLabel("Paste cURL Command:")
        main_layout.addWidget(self.curl_input_label)
        self.curl_input = QTextEdit()
        main_layout.addWidget(self.curl_input)

        # Button to parse cURL command
        self.parse_button = QPushButton("Parse cURL")
        self.parse_button.clicked.connect(self.parse_curl)
        main_layout.addWidget(self.parse_button)

        # Input field to take URL
        self.url_input_label = QLabel("URL:")
        main_layout.addWidget(self.url_input_label)
        self.url_input = QLineEdit()
        main_layout.addWidget(self.url_input)

        # Header fields
        self.headers_input_label = QLabel("Headers:")
        main_layout.addWidget(self.headers_input_label)
        self.headers_input = QTextEdit()
        main_layout.addWidget(self.headers_input)

        # Add Header button
        self.add_header_button = QPushButton("Add Header")
        self.add_header_button.clicked.connect(self.add_header)
        main_layout.addWidget(self.add_header_button)

        # Data payload field
        self.data_input_label = QLabel("Data Payload:")
        main_layout.addWidget(self.data_input_label)
        self.data_input = QTextEdit()
        main_layout.addWidget(self.data_input)

        # Button to trigger API call
        self.call_button = QPushButton("Call API")
        self.call_button.clicked.connect(self.call_api)
        main_layout.addWidget(self.call_button)

        layout.addLayout(main_layout)

        # Scrollable Output display
        scroll_area = QScrollArea()
        self.output_textedit = QTextEdit()
        self.output_textedit.setReadOnly(True)  # Make text read-only
        scroll_area.setWidgetResizable(True)  # Make the widget inside the scroll area resizable
        scroll_area.setWidget(self.output_textedit)  # Set the QTextEdit as the widget inside the scroll area
        layout.addWidget(scroll_area)

        self.setLayout(layout)
        self.setWindowTitle("API Client")
        self.resize(800, 600)  # Set initial window size

    def parse_curl(self):
        # Parse cURL command
        curl_command = self.curl_input.toPlainText()
        curl_args = shlex.split(curl_command)
        url = ""
        headers = {}
        data = ""

        for i in range(len(curl_args)):
            if curl_args[i] in ['-H', "--header"]:
                header_key, header_value = curl_args[i + 1].split(":", 1)
                headers[header_key.strip()] = header_value.strip()
            elif curl_args[i] == '-X':
                if i + 1 < len(curl_args):
                    method = curl_args[i + 1]
                    if method.upper() == 'GET':
                        break
            elif curl_args[i] in ['-d', "--data-raw"]:
                if i + 1 < len(curl_args):
                    data = curl_args[i + 1]
            elif curl_args[i].startswith("http"):
                url = curl_args[i]

        self.url_input.setText(url)
        self.headers_input.setPlainText("\n".join([f"{k}: {v}" for k, v in headers.items()]))
        self.data_input.setPlainText(data)

    def add_header(self):
        header_key, ok = QLineEdit.getText(QLineEdit(), "Enter Header Key")
        if not ok:
            return
        header_value, ok = QLineEdit.getText(QLineEdit(), "Enter Header Value")
        if not ok:
            return
        self.headers_input.append(f"{header_key.strip()}: {header_value.strip()}")

    def call_api(self):
        url = self.url_input.text()
        headers = {}
        for line in self.headers_input.toPlainText().split('\n'):
            parts = line.split(':')
            if len(parts) == 2:
                headers[parts[0].strip()] = parts[1].strip()

        data = self.data_input.toPlainText()

        # Save the request before making the API call
        request = {
            'name': f"{url} - {len(self.saved_requests) + 1}",
            'url': url,
            'headers': headers,
            'data': data
        }
        self.add_saved_request(request)

        # Make the API call
        response_text = ""
        try:
            response = requests.post(url, headers=headers, data=data)
            response_text = response.text if response.text else "No response body."
            if response.status_code == 201:
                self.worker.text_updated.emit(f"Success: Resource created successfully. Status Code: {response.status_code}\nResponse:\n{response_text}")
            elif response.status_code == 200:
                if 'application/json' in response.headers.get('content-type', ''):
                    json_data = json.loads(response_text)
                    formatted_json = json.dumps(json_data, indent=4)
                    self.worker.text_updated.emit(f"Response:\n{formatted_json}")
                else:
                    self.worker.text_updated.emit(f"Response:\n{response_text}")
            else:
                self.worker.text_updated.emit(f"Error: {response.status_code}\nResponse:\n{response_text}")
        except requests.RequestException as e:
            self.worker.text_updated.emit(f"Error: {str(e)}")

        # Save the response
        saved_response = {
            'request_name': request['name'],
            'response_text': response_text
        }
        self.saved_responses.append(saved_response)


    def load_saved_request(self, item):
        index = self.saved_requests_list.row(item)
        request = self.saved_requests[index]
        self.url_input.setText(request['url'])
        self.headers_input.setPlainText("\n".join([f"{k}: {v}" for k, v in request['headers'].items()]))
        self.data_input.setPlainText(request['data'])


    def update_text(self, text):
        self.output_textedit.setPlainText(text)

    def add_saved_request(self, request):
        self.saved_requests.append(request)
        item = QListWidgetItem(request['name'])
        self.saved_requests_list.addItem(item)


class Worker(QThread):
    text_updated = Signal(str)

    def __init__(self):
        super().__init__()
        self.url = ""
        self.headers = {}
        self.data = ""

    def set_url(self, url):
        self.url = url

    def set_headers(self, headers):
        self.headers = headers

    def set_data(self, data):
        self.data = data

    def run(self):
        try:
            response = requests.post(self.url, headers=self.headers, data=self.data)
            response_text = response.text if response.text else "No response body."
            if response.status_code == 201:
                self.text_updated.emit(f"Success: Resource created successfully. Status Code: {response.status_code}\nResponse:\n{response_text}")
            elif response.status_code == 200:
                if 'application/json' in response.headers.get('content-type', ''):
                    json_data = json.loads(response_text)
                    formatted_json = json.dumps(json_data, indent=4)
                    self.text_updated.emit(f"Response:\n{formatted_json}")
                else:
                    self.text_updated.emit(f"Response:\n{response_text}")
            else:
                self.text_updated.emit(f"Error: {response.status_code}\nResponse:\n{response_text}")
        except requests.RequestException as e:
            self.text_updated.emit(f"Error: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    client = APIClient()
    client.show()
    sys.exit(app.exec())
