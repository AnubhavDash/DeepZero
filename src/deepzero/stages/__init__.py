from deepzero.engine.stage import register_tool

from deepzero.stages.command import GenericCommand
from deepzero.stages.filter import MetadataFilter
from deepzero.stages.hash_filter import HashExclude
from deepzero.stages.ingest import FileDiscovery
from deepzero.stages.llm import GenericLLM
from deepzero.stages.semgrep_scanner import SemgrepScannerTool
from deepzero.stages.top_k import TopKSelector

register_tool("file_discovery", FileDiscovery)
register_tool("metadata_filter", MetadataFilter)
register_tool("hash_exclude", HashExclude)
register_tool("generic_llm", GenericLLM)
register_tool("generic_command", GenericCommand)
register_tool("semgrep_scanner", SemgrepScannerTool)
register_tool("top_k", TopKSelector)
