from langflow.custom import Component
from langflow.io import Output, FileInput
from langflow.schema import Data
from langflow.schema.message import Message

import json

import urllib3
from urllib3.util import Retry
from dotenv import load_dotenv
import os

load_dotenv()


SDCP_ROOT_URL = os.getenv("SDCP_ROOT_URL")
SDCP_TOKEN = os.getenv("SDCP_TOKEN")


class AudioToTextComponent(Component):
    display_name = "Audio to Text Component"
    description = "Use this component to extract text from audio file."
    documentation: str = "http://docs.langflow.org/components/custom"
    icon = "notebook-pen"
    name = "AudioToTextComponent"

    inputs = [

        FileInput(
            name="Audio_file_path",
            display_name="Audio File Path",
            info="Upload an audio file for transcription.",
            file_types=["mp3", "m4a", "webm", "mp4", "mpga", "wav", "mpeg"], 
            required=True),
    ]

    outputs = [

        Output(display_name="Output", name="output", method="build_output_data"),
        Output(display_name="Message Output", name="output_message", method="build_output_message"),
    ]

    def build_output_data(self) -> Data:
        http = urllib3.PoolManager(retries=Retry(total=3, backoff_factor=0.2))
        url = f"{SDCP_ROOT_URL}audio_processor/audio_file_to_text/"
        headers = {'accept': 'application/json'}
        if SDCP_TOKEN:
            headers['apikey'] = SDCP_TOKEN

        with open(self.Audio_file_path, 'rb') as audio_file:
           file_extension = os.path.splitext(self.Audio_file_path)[1].lstrip(".")  
           mime_type = f"audio/{file_extension}" if file_extension != "mp4" else "video/mp4"  
        
           fields = {
            "audio_file": (f"audio.{file_extension}", audio_file.read(), mime_type),  
           }
           response = http.request("POST", url, headers=headers, fields=fields)

        response = json.loads(response.data.decode('utf-8'))
        data_obj = Data(value=response["result"])
        self.status = data_obj

        return data_obj
        
    def build_output_message(self) -> Message:
        return Message(text=self.build_output_data().value)
 