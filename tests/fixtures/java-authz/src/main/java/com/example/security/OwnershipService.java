package com.example.security;

public class OwnershipService {
    public void verifyOwner(Long resourceId, String user) {
    }

    @io.github.photographed.authzradar.CheckOwnership(type = "order")
    public Object checkAlreadyInstrumented(Long id) {
        return null;
    }

    private boolean isOwnerInternal() {
        return true;
    }
}
