import json
from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist


class DiscordDataExtractor:
    """Extracts potential JSON-like user data structures from the memory of a process."""

    def __init__(self):
        # Common JSON-like pattern in Discord memory data
        self.start_tags = [b'{"id":', b'"username":', b'"discriminator":']

    def extract_json_objects(self, layer, offset, maxlen=4096):
        """Extracts JSON-like objects from memory starting at a given offset."""
        try:
            data = layer.read(offset, maxlen)
            # Attempt to find JSON blocks by searching for the start tag and curly braces
            for start_tag in self.start_tags:
                start_index = data.find(start_tag)
                if start_index != -1:
                    # Extract the potential JSON data
                    extracted_data = data[start_index:start_index + maxlen]
                    # Attempt to parse the data as JSON
                    try:
                        json_data = json.loads(extracted_data.decode("utf-8", errors="ignore"))
                        return json_data
                    except json.JSONDecodeError:
                        pass  # Continue if JSON is invalid
        except exceptions.InvalidAddressException:
            pass
        return None


class DiscordUsers(interfaces.plugins.PluginInterface):
    """Recovers Discord user data from all Discord.exe processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer for the kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", description="Windows kernel symbols"
            ),
        ]

    def _generator(self, procs):
        for proc in procs:
            proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace')
            if proc_name.lower() == "discord.exe":
                pid = proc.UniqueProcessId

                yield 0, (f"Discord.exe PID: {pid}", "", "")

                layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[layer_name]

                if not proc_layer:
                    continue

                extractor = DiscordDataExtractor()

                for offset in range(0, proc_layer.maximum_address, 0x1000):  # Iterate over memory in chunks
                    json_data = extractor.extract_json_objects(proc_layer, offset)
                    if json_data:
                        user_id = json_data.get("id", "N/A")
                        username = json_data.get("username", "N/A")
                        discriminator = json_data.get("discriminator", "N/A")
                        full_username = f"{username}#{discriminator}" if discriminator != "N/A" else username
                        yield 0, (str(pid), user_id, full_username)

    def run(self):
        procs = pslist.PsList.list_processes(
            self.context, self.config["primary"], self.config["nt_symbols"]
        )
        return renderers.TreeGrid(
            [
                ("PID", str),
                ("User ID", str),
                ("Username", str),
            ],
            self._generator(procs)
        )
