package com.ank.ankoauth2client.security;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.ank.ankoauth2client.resource.UserDto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
public class UserDetailsPrincipal extends AnkOauth2User implements UserDetails {

	private static final long serialVersionUID = 1L;
	private UserDto userDto;

	public UserDetailsPrincipal(UserDto userDto) {
		this.userDto = userDto;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return userDto.getRoles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role))
				.collect(Collectors.toList());
	}

	@Override
	public String getPassword() {
		return this.userDto.getPassword();
	}

	@Override
	public String getUsername() {

		return this.userDto.getUserName();
	}

	@Override
	public boolean isAccountNonExpired() {

		return this.userDto.getAccountFlag().isAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked() {

		return this.userDto.getAccountFlag().isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {

		return this.userDto.getAccountFlag().isCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled() {

		return this.userDto.getAccountFlag().isEnabled();
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		userDto.setPassword(null);
	}

	@Override
	public String getName() {
		return userDto.getProviderId();
	}

	public void setName(String name) {
		userDto.setProviderId(name);
	}
}
