package io.github.photographed.authzradar;

/**
 * A resource with an owner. Records with an {@code ownerId} component implement this for free:
 * {@code record Order(Long id, String ownerId, ...) implements Owned {}}.
 */
public interface Owned {

    /** The principal name (as in {@code Authentication#getName()}) of the owner. */
    String ownerId();
}
