import abc


class IResultLine(abc.ABC):
    """
    Interface for handling and comparing result line values.

    Methods:
        calculate_similarity_score(other): Calculates a similarity score between two instances
        init_from_response(check_manager): Initializes the class attributes according to responses from NMAP tests
        init_from_db(tests): Initializes the class attributes using values from a dictionary obtained from
        the NMAP database.
    """
    @abc.abstractmethod
    def calculate_similarity_score(self, other) -> int:
        """
        Calculate the similarity score between two instances.

        Args:
            other (IResultLine): Another instance to compare with.

        Returns:
            int: The similarity score.
        """
        pass

    @abc.abstractmethod
    def init_from_response(self, check_manager):
        """
        Initialize the class attributes from a CheckManager instance.

        Args:
            check_manager (CheckManager): An instance of CheckManager containing response packet of NMAP tests.
        """
        pass

    @abc.abstractmethod
    def init_from_db(self, tests):
        """
        Initialize the class attributes from a dictionary obtained from the database.

        Args:
            tests (dict): A dictionary containing NMAP database entry values.

        Raises:
            Exception: If the input is not a dictionary.
        """
        pass
