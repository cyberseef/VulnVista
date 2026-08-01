import abc

class BasePlugin(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the plugin"""
        pass

    @abc.abstractmethod
    def scan(self, url: str, response, soup=None) -> list:
        """
        Scan the given URL and response for vulnerabilities.
        Returns a list of finding dictionaries:
        [{'type': str, 'name': str, 'url': str, 'risk': str}]
        """
        pass
