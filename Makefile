all:
	@ cd searchCst && $(MAKE)
	@ cd searchKey && $(MAKE)

clean:
	@ cd searchCst && $(MAKE) clean
	@ cd searchKey && $(MAKE) clean
