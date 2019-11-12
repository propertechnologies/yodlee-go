// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AccountHolder AccountHolder
// swagger:model AccountHolder
type AccountHolder struct {

	// Date of birth.<br><br><b>Aggregated / Manual</b>: Aggregated <br><b>Applicable containers</b>: bank<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	// Read Only: true
	DateOfBirth string `json:"dateOfBirth,omitempty"`

	// Identifiers of the account holder.<br><br><b>Aggregated / Manual</b>: Aggregated <br><b>Applicable containers</b>: bank<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	// Read Only: true
	Gender string `json:"gender,omitempty"`

	// Identifiers of the account holder.<br><br><b>Aggregated / Manual</b>: Aggregated <br><b>Applicable containers</b>: bank<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	// Read Only: true
	Identifier *Identifier `json:"identifier,omitempty"`

	// Name of the account holder.<br><br><b>Aggregated / Manual</b>: Aggregated <br><b>Applicable containers</b>: bank<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul>
	// Read Only: true
	Name *Name `json:"name,omitempty"`

	// Indicates the ownership of the account.<br><br><b>Aggregated / Manual</b>: Aggregated <br><b>Applicable containers</b>: bank<br><b>Endpoints</b>:<ul><li>GET accounts</li><li>GET accounts/{accountId}</li></ul><b>Applicable Values</b><br>
	// * PRIMARY: The account holder is a primary holder of the account.<br>
	// * SECONDARY: The account holder is a secondary holder of the account.<br>
	// * CUSTODIAN: The account holder is a custodian of the account.<br>
	// * OTHERS: An account ownership other than what has been listed here.<br>
	// * POWER_OF_ATTORNEY: The account holder has a power of attorney authorizing him or her to access the account.<br>
	// * TRUSTEE: The account holder is a trustee that controls funds for the benefit of another party - an individual or a group.<br>
	// * JOINT_OWNER: The account holder has a joint ownership of the account.<br>
	// * BENEFICIARY: The account holder is a beneficiary of the account. The beneficiary has no control or ownership of the account while the account owner is alive, but is designated by the account owner to own the account upon the owner's death.<br>
	// * AAS: Indicates that the account holder is an authorized account signatory (AAS).<br>
	// * BUSINESS: Indicates that the account holder is a business.<br>
	// * DBA: Indicates that the account holder is a business using a different name, i.e., doing business as (DBA).<br>
	// * TRUST: Indicates that the account holder is a trust.<br>
	// Read Only: true
	// Enum: [PRIMARY SECONDARY CUSTODIAN OTHERS POWER_OF_ATTORNEY TRUSTEE JOINT_OWNER BENEFICIARY AAS BUSINESS DBA TRUST]
	Ownership string `json:"ownership,omitempty"`
}

// Validate validates this account holder
func (m *AccountHolder) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOwnership(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountHolder) validateIdentifier(formats strfmt.Registry) error {

	if swag.IsZero(m.Identifier) { // not required
		return nil
	}

	if m.Identifier != nil {
		if err := m.Identifier.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("identifier")
			}
			return err
		}
	}

	return nil
}

func (m *AccountHolder) validateName(formats strfmt.Registry) error {

	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if m.Name != nil {
		if err := m.Name.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("name")
			}
			return err
		}
	}

	return nil
}

var accountHolderTypeOwnershipPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["PRIMARY","SECONDARY","CUSTODIAN","OTHERS","POWER_OF_ATTORNEY","TRUSTEE","JOINT_OWNER","BENEFICIARY","AAS","BUSINESS","DBA","TRUST"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		accountHolderTypeOwnershipPropEnum = append(accountHolderTypeOwnershipPropEnum, v)
	}
}

const (

	// AccountHolderOwnershipPRIMARY captures enum value "PRIMARY"
	AccountHolderOwnershipPRIMARY string = "PRIMARY"

	// AccountHolderOwnershipSECONDARY captures enum value "SECONDARY"
	AccountHolderOwnershipSECONDARY string = "SECONDARY"

	// AccountHolderOwnershipCUSTODIAN captures enum value "CUSTODIAN"
	AccountHolderOwnershipCUSTODIAN string = "CUSTODIAN"

	// AccountHolderOwnershipOTHERS captures enum value "OTHERS"
	AccountHolderOwnershipOTHERS string = "OTHERS"

	// AccountHolderOwnershipPOWEROFATTORNEY captures enum value "POWER_OF_ATTORNEY"
	AccountHolderOwnershipPOWEROFATTORNEY string = "POWER_OF_ATTORNEY"

	// AccountHolderOwnershipTRUSTEE captures enum value "TRUSTEE"
	AccountHolderOwnershipTRUSTEE string = "TRUSTEE"

	// AccountHolderOwnershipJOINTOWNER captures enum value "JOINT_OWNER"
	AccountHolderOwnershipJOINTOWNER string = "JOINT_OWNER"

	// AccountHolderOwnershipBENEFICIARY captures enum value "BENEFICIARY"
	AccountHolderOwnershipBENEFICIARY string = "BENEFICIARY"

	// AccountHolderOwnershipAAS captures enum value "AAS"
	AccountHolderOwnershipAAS string = "AAS"

	// AccountHolderOwnershipBUSINESS captures enum value "BUSINESS"
	AccountHolderOwnershipBUSINESS string = "BUSINESS"

	// AccountHolderOwnershipDBA captures enum value "DBA"
	AccountHolderOwnershipDBA string = "DBA"

	// AccountHolderOwnershipTRUST captures enum value "TRUST"
	AccountHolderOwnershipTRUST string = "TRUST"
)

// prop value enum
func (m *AccountHolder) validateOwnershipEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, accountHolderTypeOwnershipPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *AccountHolder) validateOwnership(formats strfmt.Registry) error {

	if swag.IsZero(m.Ownership) { // not required
		return nil
	}

	// value enum
	if err := m.validateOwnershipEnum("ownership", "body", m.Ownership); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccountHolder) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccountHolder) UnmarshalBinary(b []byte) error {
	var res AccountHolder
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}