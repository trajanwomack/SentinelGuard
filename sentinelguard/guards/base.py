#abstract base class for all guards
#abstract bass class defines the interface for  other classes all guards. All guards must implement the evaluate method, which takes a GuardRequest and returns a GuardDecision.
from abc import ABC, abstractmethod

from sentinelguard.models import(
    GuardRequest,
    GuardDecision
)

class BaseGuard(ABC):
    """
    Base class for all guards.
    """

    #abstract method that must be implemented by all subclasses. It takes a GuardRequest and returns a GuardDecision.
    @abstractmethod
    def evaluate(self, request: GuardRequest) -> GuardDecision:
        """
        Evaluate the request and return a decision.

        :param request: The guard request to evaluate.
        :return: The guard decision.
        """
        pass