package com.ank.ankoauth2client.resource;

import java.io.Serializable;
import java.util.List;

import lombok.Data;

@Data
public class UserDto implements Serializable {

	private static final long serialVersionUID = 3372139466417628295L;
	private byte[] userId;
	private String userName;
	private String email;
	private String password;
	private List<String> roles;
	private AccountFlag accountFlag;
	
	private AuthType authType;

	private String name;
	private String firstName;
	private String lastName;
	private String providerId;
	private String providerName;
	private String profilePicture;

}
