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

// Verification Verification
// swagger:model Verification
type Verification struct {

	// account
	Account *VerificationAccount `json:"account,omitempty"`

	// Unique identifier for the account.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul>
	AccountID int64 `json:"accountId,omitempty"`

	// Unique identifier for the provider account.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul>
	ProviderAccountID int64 `json:"providerAccountId,omitempty"`

	// The reason the account verification failed.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul>
	// * DATA_NOT_AVAILABLE: <br><b>Description: </b>The account holder's name related details are not available at the FI site.
	// * ACCOUNT_HOLDER_MISMATCH: <br><b>Description: </b>The account verification process has failed due to account holder's data mismatch
	// * FULL_ACCOUNT_NUMBER_AND_BANK_TRANSFER_CODE_NOT_AVAILABLE: <br><b>Description: </b>The account verification process has failed as the full account number and bank transfer code are not available.
	// * FULL_ACCOUNT_NUMBER_NOT_AVAILABLE: <br><b>Description: </b>The account verification process has failed as the full account number is not available.
	// * BANK_TRANSFER_CODE_NOT_AVAILABLE: <br><b>Description: </b>The account verification process has failed as the bank transfer code is not available.
	// * EXPIRED: <br><b>Description: </b>The time limit to verify the microtransaction details has expired.
	// * DATA_MISMATCH: <br><b>Description: </b>The account verification process has failed due to data mismatch.
	// * INSTRUCTION_GENERATION_ERROR: <br><b>Description: </b>The consumer's account verification has failed.
	// Read Only: true
	// Enum: [DATA_NOT_AVAILABLE ACCOUNT_HOLDER_MISMATCH FULL_ACCOUNT_NUMBER_AND_BANK_TRANSFER_CODE_NOT_AVAILABLE FULL_ACCOUNT_NUMBER_NOT_AVAILABLE BANK_TRANSFER_CODE_NOT_AVAILABLE EXPIRED DATA_MISMATCH INSTRUCTION_GENERATION_ERROR]
	Reason string `json:"reason,omitempty"`

	// The date of the account verification.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul>
	// Read Only: true
	VerificationDate string `json:"verificationDate,omitempty"`

	// Unique identifier for the verification request.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul>
	// Read Only: true
	VerificationID int64 `json:"verificationId,omitempty"`

	// The status of the account verification.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul><br><b>Applicable Values</b>
	// * INITIATED: <br><b>Description: </b>The account verification process is initiated.<br>
	// * DEPOSITED: <br><b>Description: </b>The microdeposits and debits for the CDV process are posted to the consumer's account.<br>
	// * SUCCESS: <br><b>Description: </b>The consumer's account verification is successful.<br>
	// * FAILED: <br><b>Description: </b>Due to technical issues Yodlee could not post the microtransactions in the user's account.<br>
	// Read Only: true
	// Enum: [INITIATED DEPOSITED SUCCESS FAILED]
	VerificationStatus string `json:"verificationStatus,omitempty"`

	// The account verification type.<br><br><b>Endpoints</b>:<ul><li>POST verification</li><li>GET verification</li><li>PUT verification</li></ul><br><b>Applicable Values</b>
	// Enum: [MATCHING CHALLENGE_DEPOSIT]
	VerificationType string `json:"verificationType,omitempty"`
}

// Validate validates this verification
func (m *Verification) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReason(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerificationStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerificationType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Verification) validateAccount(formats strfmt.Registry) error {

	if swag.IsZero(m.Account) { // not required
		return nil
	}

	if m.Account != nil {
		if err := m.Account.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account")
			}
			return err
		}
	}

	return nil
}

var verificationTypeReasonPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["DATA_NOT_AVAILABLE","ACCOUNT_HOLDER_MISMATCH","FULL_ACCOUNT_NUMBER_AND_BANK_TRANSFER_CODE_NOT_AVAILABLE","FULL_ACCOUNT_NUMBER_NOT_AVAILABLE","BANK_TRANSFER_CODE_NOT_AVAILABLE","EXPIRED","DATA_MISMATCH","INSTRUCTION_GENERATION_ERROR"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		verificationTypeReasonPropEnum = append(verificationTypeReasonPropEnum, v)
	}
}

const (

	// VerificationReasonDATANOTAVAILABLE captures enum value "DATA_NOT_AVAILABLE"
	VerificationReasonDATANOTAVAILABLE string = "DATA_NOT_AVAILABLE"

	// VerificationReasonACCOUNTHOLDERMISMATCH captures enum value "ACCOUNT_HOLDER_MISMATCH"
	VerificationReasonACCOUNTHOLDERMISMATCH string = "ACCOUNT_HOLDER_MISMATCH"

	// VerificationReasonFULLACCOUNTNUMBERANDBANKTRANSFERCODENOTAVAILABLE captures enum value "FULL_ACCOUNT_NUMBER_AND_BANK_TRANSFER_CODE_NOT_AVAILABLE"
	VerificationReasonFULLACCOUNTNUMBERANDBANKTRANSFERCODENOTAVAILABLE string = "FULL_ACCOUNT_NUMBER_AND_BANK_TRANSFER_CODE_NOT_AVAILABLE"

	// VerificationReasonFULLACCOUNTNUMBERNOTAVAILABLE captures enum value "FULL_ACCOUNT_NUMBER_NOT_AVAILABLE"
	VerificationReasonFULLACCOUNTNUMBERNOTAVAILABLE string = "FULL_ACCOUNT_NUMBER_NOT_AVAILABLE"

	// VerificationReasonBANKTRANSFERCODENOTAVAILABLE captures enum value "BANK_TRANSFER_CODE_NOT_AVAILABLE"
	VerificationReasonBANKTRANSFERCODENOTAVAILABLE string = "BANK_TRANSFER_CODE_NOT_AVAILABLE"

	// VerificationReasonEXPIRED captures enum value "EXPIRED"
	VerificationReasonEXPIRED string = "EXPIRED"

	// VerificationReasonDATAMISMATCH captures enum value "DATA_MISMATCH"
	VerificationReasonDATAMISMATCH string = "DATA_MISMATCH"

	// VerificationReasonINSTRUCTIONGENERATIONERROR captures enum value "INSTRUCTION_GENERATION_ERROR"
	VerificationReasonINSTRUCTIONGENERATIONERROR string = "INSTRUCTION_GENERATION_ERROR"
)

// prop value enum
func (m *Verification) validateReasonEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, verificationTypeReasonPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Verification) validateReason(formats strfmt.Registry) error {

	if swag.IsZero(m.Reason) { // not required
		return nil
	}

	// value enum
	if err := m.validateReasonEnum("reason", "body", m.Reason); err != nil {
		return err
	}

	return nil
}

var verificationTypeVerificationStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["INITIATED","DEPOSITED","SUCCESS","FAILED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		verificationTypeVerificationStatusPropEnum = append(verificationTypeVerificationStatusPropEnum, v)
	}
}

const (

	// VerificationVerificationStatusINITIATED captures enum value "INITIATED"
	VerificationVerificationStatusINITIATED string = "INITIATED"

	// VerificationVerificationStatusDEPOSITED captures enum value "DEPOSITED"
	VerificationVerificationStatusDEPOSITED string = "DEPOSITED"

	// VerificationVerificationStatusSUCCESS captures enum value "SUCCESS"
	VerificationVerificationStatusSUCCESS string = "SUCCESS"

	// VerificationVerificationStatusFAILED captures enum value "FAILED"
	VerificationVerificationStatusFAILED string = "FAILED"
)

// prop value enum
func (m *Verification) validateVerificationStatusEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, verificationTypeVerificationStatusPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Verification) validateVerificationStatus(formats strfmt.Registry) error {

	if swag.IsZero(m.VerificationStatus) { // not required
		return nil
	}

	// value enum
	if err := m.validateVerificationStatusEnum("verificationStatus", "body", m.VerificationStatus); err != nil {
		return err
	}

	return nil
}

var verificationTypeVerificationTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["MATCHING","CHALLENGE_DEPOSIT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		verificationTypeVerificationTypePropEnum = append(verificationTypeVerificationTypePropEnum, v)
	}
}

const (

	// VerificationVerificationTypeMATCHING captures enum value "MATCHING"
	VerificationVerificationTypeMATCHING string = "MATCHING"

	// VerificationVerificationTypeCHALLENGEDEPOSIT captures enum value "CHALLENGE_DEPOSIT"
	VerificationVerificationTypeCHALLENGEDEPOSIT string = "CHALLENGE_DEPOSIT"
)

// prop value enum
func (m *Verification) validateVerificationTypeEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, verificationTypeVerificationTypePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Verification) validateVerificationType(formats strfmt.Registry) error {

	if swag.IsZero(m.VerificationType) { // not required
		return nil
	}

	// value enum
	if err := m.validateVerificationTypeEnum("verificationType", "body", m.VerificationType); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Verification) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Verification) UnmarshalBinary(b []byte) error {
	var res Verification
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}