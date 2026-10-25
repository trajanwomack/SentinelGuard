#import sentinelguard.guards.base to
from sentinelguard.guards.base import BaseGuard

#import sentinelguard.models to use the Action, GuardRequest, and GuardDecision classes. The Action class is an enumeration that defines the possible actions that can be taken by the guard (allow or deny). The GuardRequest class is a dataclass that represents a request to be evaluated by the guard. The GuardDecision class is a dataclass that represents the decision made by the guard after evaluating the request.
from sentinelguard.models import(
    Action,
    GuardRequest,
    GuardDecision
)


class SentinelGuard:
    #__init_ method initializes the SentinelGuard instance and creates an empty list of guards. The guards list will hold instances of classes that inherit from BaseGuard, which is an abstract base class for all guards. Each guard in the list will be responsible for evaluating requests and making decisions based on their specific logic.
    def __init__(self):
        self.guards: list[BaseGuard] = []

    #register_guard method takes a guard instance as an argument and adds it to the guards list. It checks if the provided guard is an instance of BaseGuard, and if not, it raises a TypeError. This ensures that only valid guard instances are registered with the SentinelGuard.
    def register_guard(self, guard: BaseGuard):


        #if isinstance checks if the provided guard is an instance of BaseGuard. If it is not, a TypeError is raised with the message "Guard must be an instance of BaseGuard." This ensures that only valid guard instances are registered with the SentinelGuard.
        if not isinstance(guard, BaseGuard):
            raise TypeError("Guard must be an instance of BaseGuard.")
        self.guards.append(guard)

    #evaluate method takes a GuardRequest as an argument and evaluates it against all registered guards. It iterates through the list of guards and calls their evaluate method, passing the request. If any guard returns a decision with an action of Deny, that decision is returned immediately. If all guards approve the request (i.e., return Allow), a final decision with an action of Allow is returned. If no guards are registered or if an exception occurs during evaluation, a Deny decision is returned with an appropriate reason.
    def evaluate(
            self,
            request: GuardRequest
    ) -> GuardDecision:


        #if there are no guards registered, a GuardDecision with an action of Deny is returned, along with a reason indicating that no guards are available to evaluate the request. The guard_name is set to "SentinelGuard" to indicate that the decision was made by the SentinelGuard itself.
        if not self.guards:
            return GuardDecision(
                action=Action.Deny,
                reason="No guards registered to evaluate the request.",
                guard_name="SentinelGuard"
            )

        #iterates through the list of registered guards and calls their evaluate method, passing the GuardRequest. If a guard returns a decision with an action of Deny, that decision is returned immediately. If all guards approve the request (i.e., return Allow), a final decision with an action of Allow is returned. If an exception occurs during evaluation, a Deny decision is returned with a reason indicating that the security guard evaluation failed.
        for guard in self.guards:

            #try-except block is used to handle any exceptions that may occur during the evaluation of a guard. If an exception is raised, a GuardDecision with an action of Deny is returned, along with a reason indicating that the security guard evaluation failed. The guard_name is set to "SentinelGuard" to indicate that the decision was made by the SentinelGuard itself.
            try:
                decision = guard.evaluate(request)

                if not isinstance(decision, GuardDecision):
                    raise TypeError("Invalid guard decision")

                if not isinstance(decision.action, Action):
                    raise TypeError("Invalid guard decision action")

                if decision.action == Action.Deny:
                    return decision

            except Exception:
                return GuardDecision(
                    action=Action.Deny,
                    reason="Security guard evaluation failed.",
                    guard_name="SentinelGuard"
                )

        #allow if all guards approve the request (i.e., return Allow), a final decision with an action of Allow is returned. The reason indicates that all guards approved the request, and the guard_name is set to "SentinelGuard" to indicate that the decision was made by the SentinelGuard itself.
        return GuardDecision(
            action=Action.Allow,
            reason="All guards approved the request.",
            guard_name="SentinelGuard"
        )
    