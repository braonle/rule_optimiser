""" Basic abstract class for policy rule from ZIA"""
import abc
from typing import Self
from abc import ABCMeta

MAX_DISTANCE = 255


class PolicyRule(metaclass=ABCMeta):
    """
        Base class for policy rules with abstract methods. Instances are used by
        optimiser to find sets of similar rules.

        Custom fields are later used as column names by Excel export, ignoring functions
        and names, starting with underscore '_'.
    """

    @abc.abstractmethod
    def distance_from(self, policy_rule: Self) -> float:
        """
            Abstract method. Defines distance to another rule.

            :param PolicyRule policy_rule: vector to compute distance to

            :return Real value of distance to vector
        """

    def distance_to_set(self, st: set[Self], max_dist: int = MAX_DISTANCE,
                        distance_mapper: dict[Self, dict[Self, float]] = None) -> float:
        """
            Calculate distance to a set of rules as max of corresponding distances.

            :param set[PolicyRule] st: set to calculate distance to
            :param int max_dist: maximum distance to compute to
            :param dict[PolicyRule, dict[PolicyRule, float]] distance_mapper: pairwise
                    pre-computed distances

            :return Real value of distance to the set
        """
        distance = 0

        for x in st:
            if distance_mapper is None:
                distance = max(distance, self.distance_from(x))
            else:
                distance = distance_mapper[self][x]

            if distance > max_dist:
                return distance

        return distance


    @staticmethod
    def distance_within_set(st: set, max_dist: int = MAX_DISTANCE,
                            distance_mapper: dict[Self, dict[Self, float]] = None) -> float:
        """
            Calculate distance within a set of rules. Distance – max of distances
            between any two vectors of the set.

            :param set[PolicyRule] st: set to calculate distance within
            :param int max_dist: maximum distance to compute to

            :return Real value of distance within the set
        """
        distance = 0

        lst = list(st)

        while len(lst) > 1:
            elem = lst.pop()
            for x in lst:
                if distance_mapper is None:
                    distance = max(distance, x.distance_from(elem))
                else:
                    distance = distance_mapper[elem][x]

                if distance > max_dist:
                    return distance

        return distance

    def to_dict(self) -> dict[str]:
        """
            Convert rule to dict for further JSON formatting.

            :return: dict[str]
        """
        return self.__dict__

    @abc.abstractmethod
    def _key(self) -> tuple:
        """
            Abstract method. Defines tuple of key fields to use in __hash__ and __eq__ methods.
            Required for vector uniqueness within a set.

            :return Tuple with values of key fields
        """

    def __hash__(self):
        return hash(self._key())

    def __eq__(self, other: Self) -> bool:
        if isinstance(other, PolicyRule):
            return self._key() == other._key()
        return NotImplemented
