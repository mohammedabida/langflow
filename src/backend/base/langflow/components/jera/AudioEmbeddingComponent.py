from langflow.custom import Component
from langflow.io import Output
from langflow.inputs import FileInput, IntInput
from langflow.schema import Data
import requests
from dotenv import load_dotenv
import os

load_dotenv()


SDCP_ROOT_URL = os.getenv("SDCP_ROOT_URL")
SDCP_TOKEN = os.getenv("SDCP_TOKEN")


class AudioEmbeddingComponent(Component):
    display_name="Audio Embedding"
    description= "Process audio file and generate embeddings"
    icon="special_component"
    name="AudioEmbedding"
    
    inputs=[
        FileInput(
            name= "audio_file",
            display_name="Audio File",
            info="Upload an audio file to be processed.",
            file_types=["mp3", "m4a", "webm", "mp4", "mpga", "wav", "mpeg"],
            required=True,
        ),
        IntInput(
            name="split_length",
            display_name="Split Length",
            info="Split length in milliseconds.",
            value=60000
        )
    ]
    
    outputs = [
        Output(display_name="Output", name="output", method="build_output_data")
    ]
    
    def build_output_data(self) -> Data:
        with open(self.audio_file, "rb") as audio_file:
            file_extension = os.path.splitext(self.audio_file)[1].lstrip(".")
            mime_type = f"audio/{file_extension}" if file_extension != "mp4" else "video/mp4"  # MUDEI: Ajustei MIME type dinamicamente

            files = {
                "audio_file": (f"audio.{file_extension}", audio_file.read(), mime_type)  # MUDEI: Usando MIME correto
            }
            data = {"split_length": self.split_length}
        embedding_url=f"{SDCP_ROOT_URL}embedding/audio-embedding"
        if SDCP_TOKEN:
            headers = {"apikey": SDCP_TOKEN}
            embedding_result = requests.post(embedding_url, data=data, files=files, headers=headers)
        else:
            embedding_result = requests.post(embedding_url, data=data, files=files)
        
        return Data(value=embedding_result.json())


    
    
    
    
    