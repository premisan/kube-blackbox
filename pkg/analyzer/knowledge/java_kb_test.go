package knowledge

import (
	"testing"
)

func TestAnalyzeJavaDeepCrash_CausedByUnwrap(t *testing.T) {
	logs := `
org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'userController': Injection of autowired dependencies failed
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessProperties(AutowiredAnnotationBeanPostProcessor.java:515)
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.populateBean(AbstractAutowireCapableBeanFactory.java:1439)
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'userService': Unsatisfied dependency expressed through field 'dataSource'
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor$AutowiredFieldElement.resolveFieldValue(AutowiredAnnotationBeanPostProcessor.java:787)
Caused by: com.zaxxer.hikari.pool.HikariPool$PoolInitializationException: Failed to initialize pool: Connection refused
	at com.zaxxer.hikari.pool.HikariPool.checkFailFast(HikariPool.java:549)
Caused by: java.sql.SQLNonTransientConnectionException: Could not connect to address=(host=10.96.0.4)(port=3306): Connection refused
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:110)
	at com.company.payment.repository.OrderRepository.findPending(OrderRepository.java:42)
`

	analysis := AnalyzeJavaDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}

	if !analysis.IsUnwrapped {
		t.Errorf("expected IsUnwrapped to be true")
	}
	if analysis.TopExceptionClass != "org.springframework.beans.factory.BeanCreationException" {
		t.Errorf("expected top exception BeanCreationException, got %q", analysis.TopExceptionClass)
	}
	if analysis.RootExceptionClass != "java.sql.SQLNonTransientConnectionException" {
		t.Errorf("expected root exception SQLNonTransientConnectionException, got %q", analysis.RootExceptionClass)
	}
	if len(analysis.CausedByChain) != 3 {
		t.Errorf("expected 3 Caused by steps, got %d", len(analysis.CausedByChain))
	}
	if analysis.CulpritCode == nil || analysis.CulpritCode.File != "OrderRepository.java" || analysis.CulpritCode.Line != 42 {
		t.Errorf("expected culprit OrderRepository.java:42, got %+v", analysis.CulpritCode)
	}
}

func TestAnalyzeJavaDeepCrash_CircularBean(t *testing.T) {
	logs := `
org.springframework.beans.factory.BeanCurrentlyInCreationException: Error creating bean with name 'orderService': Requested bean is currently in creation
The dependencies of some of the beans in the application context form a cycle:
┌─────┐
|  orderService (field private com.example.PaymentService com.example.OrderService.paymentService)
↑     ↓
|  paymentService (field private com.example.OrderService com.example.PaymentService.orderService)
└─────┘
`
	analysis := AnalyzeJavaDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.Framework != "Spring Boot" {
		t.Errorf("expected Spring Boot framework, got %q", analysis.Framework)
	}
	if analysis.SummaryKo == "" || analysis.SuggestedFixKo == "" {
		t.Errorf("expected non-empty localized summary and fix")
	}
}

func TestAnalyzeJavaDeepCrash_HikariTimeout(t *testing.T) {
	logs := `
java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms.
	at com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
	at com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:197)
	at com.app.billing.InvoiceService.generateInvoice(InvoiceService.java:88)
`
	analysis := AnalyzeJavaDeepCrash(logs)
	if analysis == nil {
		t.Fatalf("expected non-nil analysis")
	}
	if analysis.RootExceptionClass != "java.sql.SQLTransientConnectionException" {
		t.Errorf("expected SQLTransientConnectionException, got %q", analysis.RootExceptionClass)
	}
	if analysis.CulpritCode == nil || analysis.CulpritCode.File != "InvoiceService.java" || analysis.CulpritCode.Line != 88 {
		t.Errorf("expected InvoiceService.java:88, got %+v", analysis.CulpritCode)
	}
}
