CREATE TABLE public.user_auths
(
    email text NOT NULL,
    password text,
    role text,
    organization text,
    employee_count integer,
    designation text,
    confirmation_accepted boolean,
    PRIMARY KEY (email)
)
WITH (
    OIDS = FALSE
);

ALTER TABLE public.user_auths
    OWNER to postgres;

ALTER TABLE public.user_auths
    ALTER COLUMN confirmation_accepted SET DEFAULT False;