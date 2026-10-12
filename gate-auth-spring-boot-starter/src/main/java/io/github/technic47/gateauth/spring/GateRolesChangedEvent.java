package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.RoleCatalog;

/**
 * Published when the app received a newer role catalog from the gate (spec §4.5): at start, and whenever the
 * admin changed roles in the gate. Listen with {@code @EventListener} to react, e.g. to show new roles as
 * "not configured yet".
 *
 * @param previous the catalog before, or {@code null} for the first one
 * @param current  the new catalog
 */
public record GateRolesChangedEvent(RoleCatalog previous, RoleCatalog current) {
}
