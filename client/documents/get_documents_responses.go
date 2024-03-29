// Code generated by go-swagger; DO NOT EDIT.

package documents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// GetDocumentsReader is a Reader for the GetDocuments structure.
type GetDocumentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDocumentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDocumentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDocumentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetDocumentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetDocumentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetDocumentsOK creates a GetDocumentsOK with default headers values
func NewGetDocumentsOK() *GetDocumentsOK {
	return &GetDocumentsOK{}
}

/*GetDocumentsOK handles this case with default header values.

OK
*/
type GetDocumentsOK struct {
	Payload *models.DocumentResponse
}

func (o *GetDocumentsOK) Error() string {
	return fmt.Sprintf("[GET /documents][%d] getDocumentsOK  %+v", 200, o.Payload)
}

func (o *GetDocumentsOK) GetPayload() *models.DocumentResponse {
	return o.Payload
}

func (o *GetDocumentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DocumentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDocumentsBadRequest creates a GetDocumentsBadRequest with default headers values
func NewGetDocumentsBadRequest() *GetDocumentsBadRequest {
	return &GetDocumentsBadRequest{}
}

/*GetDocumentsBadRequest handles this case with default header values.

Y800 : Invalid value for accountId<br>Y800 : Invalid value for fromDate<br>Y800 : Invalid value for toDate<br>Y800 : Invalid value for docType
*/
type GetDocumentsBadRequest struct {
	Payload *models.YodleeError
}

func (o *GetDocumentsBadRequest) Error() string {
	return fmt.Sprintf("[GET /documents][%d] getDocumentsBadRequest  %+v", 400, o.Payload)
}

func (o *GetDocumentsBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *GetDocumentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDocumentsUnauthorized creates a GetDocumentsUnauthorized with default headers values
func NewGetDocumentsUnauthorized() *GetDocumentsUnauthorized {
	return &GetDocumentsUnauthorized{}
}

/*GetDocumentsUnauthorized handles this case with default header values.

Unauthorized
*/
type GetDocumentsUnauthorized struct {
}

func (o *GetDocumentsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /documents][%d] getDocumentsUnauthorized ", 401)
}

func (o *GetDocumentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetDocumentsNotFound creates a GetDocumentsNotFound with default headers values
func NewGetDocumentsNotFound() *GetDocumentsNotFound {
	return &GetDocumentsNotFound{}
}

/*GetDocumentsNotFound handles this case with default header values.

Not Found
*/
type GetDocumentsNotFound struct {
}

func (o *GetDocumentsNotFound) Error() string {
	return fmt.Sprintf("[GET /documents][%d] getDocumentsNotFound ", 404)
}

func (o *GetDocumentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
