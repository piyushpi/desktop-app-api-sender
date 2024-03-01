import sys
import shlex
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QScrollArea, QSizePolicy, QLabel
from PySide6.QtCore import Qt, QThread, Signal
import requests
import json


class APIClient(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()
        self.worker = Worker()
        self.worker.text_updated.connect(self.update_text)

    def init_ui(self):
        layout = QVBoxLayout()

        # Paste cURL command
        self.curl_input_label = QLabel("Paste cURL Command:")
        layout.addWidget(self.curl_input_label)
        self.curl_input = QTextEdit()
        layout.addWidget(self.curl_input)

        # Button to parse cURL command
        self.parse_button = QPushButton("Parse cURL")
        self.parse_button.clicked.connect(self.parse_curl)
        layout.addWidget(self.parse_button)

        # Input field to take URL
        self.url_input_label = QLabel("URL:")
        layout.addWidget(self.url_input_label)
        self.url_input = QLineEdit()
        layout.addWidget(self.url_input)

        # Header fields
        self.headers_input_label = QLabel("Headers:")
        layout.addWidget(self.headers_input_label)
        self.headers_input = QTextEdit()
        layout.addWidget(self.headers_input)

        # Data payload field
        self.data_input_label = QLabel("Data Payload:")
        layout.addWidget(self.data_input_label)
        self.data_input = QTextEdit()
        layout.addWidget(self.data_input)

        # Button to trigger API call
        self.call_button = QPushButton("Call API")
        self.call_button.clicked.connect(self.call_api)
        layout.addWidget(self.call_button)

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
            if curl_args[i] == '-H':
                header_key, header_value = curl_args[i + 1].split(":", 1)
                headers[header_key.strip()] = header_value.strip()
            elif curl_args[i] == '-X':
                if i + 1 < len(curl_args):
                    method = curl_args[i + 1]
                    if method.upper() == 'GET':
                        break
            elif curl_args[i] == '-d':
                if i + 1 < len(curl_args):
                    data = curl_args[i + 1]
            elif curl_args[i].startswith("http"):
                url = curl_args[i]

        self.url_input.setText(url)
        self.headers_input.setPlainText("\n".join([f"{k}: {v}" for k, v in headers.items()]))
        self.data_input.setPlainText(data)

    def call_api(self):
        url = self.url_input.text()
        headers = {}
        for line in self.headers_input.toPlainText().split('\n'):
            parts = line.split(':')
            if len(parts) == 2:
                headers[parts[0].strip()] = parts[1].strip()

        data = self.data_input.toPlainText()

        self.worker.set_url(url)
        self.worker.set_headers(headers)
        self.worker.set_data(data)
        self.worker.start()

    def update_text(self, text):
        self.output_textedit.setPlainText(text)


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
