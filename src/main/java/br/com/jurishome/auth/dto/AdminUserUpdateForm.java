package br.com.jurishome.auth.dto;

import java.util.LinkedHashSet;
import java.util.Set;

import br.com.jurishome.auth.domain.Role;
import jakarta.validation.constraints.NotEmpty;

public class AdminUserUpdateForm {

    @NotEmpty(message = "Selecione pelo menos um perfil.")
    private Set<Role> roles = new LinkedHashSet<>();
    private boolean enabled;

    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
