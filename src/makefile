JAVAC=javac
.SUFFIXES:.java .class
.java.class:
	$(JAVAC) $*.java
CLASSES = \
	ATM.java \
	Bank.java \
	Encrypt.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	rm -f *.class
