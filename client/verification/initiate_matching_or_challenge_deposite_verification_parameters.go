// Code generated by go-swagger; DO NOT EDIT.

package verification

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// NewInitiateMatchingOrChallengeDepositeVerificationParams creates a new InitiateMatchingOrChallengeDepositeVerificationParams object
// with the default values initialized.
func NewInitiateMatchingOrChallengeDepositeVerificationParams() *InitiateMatchingOrChallengeDepositeVerificationParams {
	var ()
	return &InitiateMatchingOrChallengeDepositeVerificationParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewInitiateMatchingOrChallengeDepositeVerificationParamsWithTimeout creates a new InitiateMatchingOrChallengeDepositeVerificationParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewInitiateMatchingOrChallengeDepositeVerificationParamsWithTimeout(timeout time.Duration) *InitiateMatchingOrChallengeDepositeVerificationParams {
	var ()
	return &InitiateMatchingOrChallengeDepositeVerificationParams{

		timeout: timeout,
	}
}

// NewInitiateMatchingOrChallengeDepositeVerificationParamsWithContext creates a new InitiateMatchingOrChallengeDepositeVerificationParams object
// with the default values initialized, and the ability to set a context for a request
func NewInitiateMatchingOrChallengeDepositeVerificationParamsWithContext(ctx context.Context) *InitiateMatchingOrChallengeDepositeVerificationParams {
	var ()
	return &InitiateMatchingOrChallengeDepositeVerificationParams{

		Context: ctx,
	}
}

// NewInitiateMatchingOrChallengeDepositeVerificationParamsWithHTTPClient creates a new InitiateMatchingOrChallengeDepositeVerificationParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewInitiateMatchingOrChallengeDepositeVerificationParamsWithHTTPClient(client *http.Client) *InitiateMatchingOrChallengeDepositeVerificationParams {
	var ()
	return &InitiateMatchingOrChallengeDepositeVerificationParams{
		HTTPClient: client,
	}
}

/*InitiateMatchingOrChallengeDepositeVerificationParams contains all the parameters to send to the API endpoint
for the initiate matching or challenge deposite verification operation typically these are written to a http.Request
*/
type InitiateMatchingOrChallengeDepositeVerificationParams struct {

	/*VerificationParam
	  verification information

	*/
	VerificationParam *models.VerificationRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) WithTimeout(timeout time.Duration) *InitiateMatchingOrChallengeDepositeVerificationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) WithContext(ctx context.Context) *InitiateMatchingOrChallengeDepositeVerificationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) WithHTTPClient(client *http.Client) *InitiateMatchingOrChallengeDepositeVerificationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithVerificationParam adds the verificationParam to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) WithVerificationParam(verificationParam *models.VerificationRequest) *InitiateMatchingOrChallengeDepositeVerificationParams {
	o.SetVerificationParam(verificationParam)
	return o
}

// SetVerificationParam adds the verificationParam to the initiate matching or challenge deposite verification params
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) SetVerificationParam(verificationParam *models.VerificationRequest) {
	o.VerificationParam = verificationParam
}

// WriteToRequest writes these params to a swagger request
func (o *InitiateMatchingOrChallengeDepositeVerificationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.VerificationParam != nil {
		if err := r.SetBodyParam(o.VerificationParam); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
