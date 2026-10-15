"""
Sentinel AI - Access Control Layer (ACL)
Enforces backend authorization and document scope checks BEFORE retrieval.
The model is never allowed to approve access or override access controls.
"""
from typing import List, Set
from backend.auth.models import AuthenticatedUser

class AccessControlService:
    def is_authorized_for_scope(self, user: AuthenticatedUser, required_scope: str) -> bool:
        """
        Verifies if the authenticated user has permission to view a document scope.
        """
        user_scopes: Set[str] = set(user.allowed_doc_scopes)
        if "admin_all" in user_scopes or "*" in user_scopes:
            return True
        return required_scope in user_scopes

    def filter_authorized_scopes(self, user: AuthenticatedUser, requested_scopes: List[str]) -> List[str]:
        """
        Returns only the scopes for which the user is explicitly authorized.
        """
        return [scope for scope in requested_scopes if self.is_authorized_for_scope(user, scope)]

acl_service = AccessControlService()
