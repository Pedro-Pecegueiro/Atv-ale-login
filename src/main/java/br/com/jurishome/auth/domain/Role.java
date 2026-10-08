package br.com.jurishome.auth.domain;

public enum Role {
    ROLE_USER("Cliente"),
    ROLE_MODERATOR("Equipe juridica"),
    ROLE_ADMIN("Administrador");

    private final String label;

    Role(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
