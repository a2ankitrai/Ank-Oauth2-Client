package com.ank.ankoauth2client.resource;

import java.io.Serializable;

import lombok.Data;

@Data
public class AccountFlag implements Serializable {

	private static final long serialVersionUID = 5333516826247230734L;
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialsNonExpired;
	private boolean enabled;

}
