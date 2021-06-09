package de.qtc.rmg.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import de.qtc.rmg.internal.RMGOption;

/**
 * remote-method-guesser uses commons-cli for argument parsing. While being a useful
 * library, it misses support module based argument parsing and some other features that
 * are available in more modern argument parsers. Nonetheless, currently we still stick to
 * it and the Parameters annotation class is used to implement some additional argument
 * checking.
 *
 * Each operation supported by the Dispatcher class can be marked by this annotation.
 * The count attribute specifies how many positional arguments the corresponding operation
 * expects. The requires attribute can be used to specify which options are required for the
 * action.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Parameters {
    int count() default 0;
    RMGOption[] requires() default {};
}
