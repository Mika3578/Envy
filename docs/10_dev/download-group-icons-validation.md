# Download-group icon validation

The automated schema-icon regression checks that every `<icon path="...">`
reference in `Schemas/*.xml` resolves to a checked-in `.ico` resource. The
runtime loader additionally verifies that malformed, partial, or missing
resources leave every schema icon size at the generic file icon rather than an
invalid image-list index.

Manual UI checks for the maintainer:

1. Start Envy with the default skin and open Downloads. Confirm the default,
   schema-backed, and custom download groups show a 16px icon without clipping.
2. Hover and select each group. Confirm the icon remains aligned and follows
   the skin's hover/active/disabled background states.
3. Enable alternate icons, restart, and repeat the group and schema combo
   checks. Disable alternate icons and confirm the normal/default icon returns.
4. Test at 100%, 125%, 150%, and 200% display scaling. Confirm the icon stays
   centered in the group tab and schema combo row.
5. Where other shell-icon consumers request larger entries, verify the 16px,
   32px, and 48px image-list entries each render the matching icon without
   substituting a different size or clipping it.
6. Temporarily remove or rename one schema `.ico` file in a private test copy.
   Confirm the group and combo show the generic file icon and do not assert or
   display a blank/invalid image.
